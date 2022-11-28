#include "common/common.h"
#include "common/log.h"
#include "common/socket.h"
#include "common/packet.h"

#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <termios.h>
#include <signal.h>

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>

#include "miniaudio.h"

#include <threads.h>

#define      with ";"
#define     plain "0" /* or "" */
#define        no "2"
#define    bright "1"
#define       dim "2"
#define    italic "3"
#define underline "4"
#define   reverse "7"

#define        fg "3"
#define        bg "4"
#define     br_fg "9"
#define     br_bg "10"
#define     black "0"
#define       red "1"
#define     green "2"
#define    yellow "3"
#define      blue "4"
#define   magenta "5"
#define      cyan "6"
#define     white "7"

#define    alt_buf "?1049"
#define       curs "?25"
#define term_clear "2J"
#define clear_line "2K"
#define       high "h"
#define        low "l"
#define       jump "H"

#define esc "\x1b"
#define esca esc "["
#define wfg "38;5;"
#define wbg "48;5;"
#define color "m"
#define fmt(f) esca f "m"

#define say(s) write(1,s,sizeof(s))
#define sz(s) (sizeof(s)/sizeof(*s))

#define INPUT_BUFFER_SIZE  2048
#define CHAT_BUFFER_SIZE   2048
#define OUTPUT_BUFFER_SIZE 2048
#define NUM_CHAT_LINES     1024

struct termios initial;
uint16_t width, height;
uint16_t input_offset = 0;
uint16_t chat_offset = 0;
uint8_t buffer[INPUT_BUFFER_SIZE] = {0};
uint8_t chat_buffer[CHAT_BUFFER_SIZE] = {0};
uint8_t output_buffer[OUTPUT_BUFFER_SIZE] = {0};
uint8_t *lines[NUM_CHAT_LINES] = {0};
uint32_t num_lines = 0;

enum keys {
    /* These keycodes are mapped to terminal codes */
    KEY_NULL      = 0,
    KEY_ENTER     = 13,
    KEY_ESC       = 27,
    KEY_BACKSPACE = 127,

    /* These are derived from escape codes */
    KEY_INVALID = 1024,
    KEY_ARROW_LEFT,
    KEY_ARROW_RIGHT,
    KEY_ARROW_UP,
    KEY_ARROW_DOWN,
};

size_t textsz(const char* str) {
	//returns size of string without formatting characters
	size_t sz = 0, i = 0;

	count: if (str[i] == 0) return sz;
		else if (str[i] == '\x1b') goto skip;
		else { ++i; ++sz; goto count; }

	skip: if (str[i] != 'm') {
		++i; goto skip;
	} else goto count;
};

void restore(void) {
    say(//enter alternate buffer if we haven't already
        esca alt_buf high

        //clean up the buffer
        esca term_clear

        //show the cursor
        esca curs high

        //return to the main buffer
        esca alt_buf low);

    //restore original termios params
    tcsetattr(1, TCSANOW, &initial);
}

void restore_die(int i) {
    (void) i;
    // since atexit has already registered a handler,
    // a call to exit(3) is all we actually need
    exit(1);
}

void repaint(void);

void resize(int i) {
    (void) i;
    struct winsize ws;
    ioctl(1, TIOCGWINSZ, &ws);
    width = ws.ws_col;
    height = ws.ws_row;
    say(esca term_clear);
    repaint();
}

void initterm(void) {
    // since we're using printf here, which doesn't play nicely
    // with non-canonical mode, we need to turn off buffering.
    setvbuf(stdout, NULL, _IONBF, 0);

    struct termios t;
    tcgetattr(1, &t);
    initial = t;
    t.c_lflag &= (~ECHO & ~ICANON);
    tcsetattr(1, TCSANOW, &t);

    atexit(restore);
    signal(SIGTERM, restore_die);
    signal(SIGINT, restore_die);

    say(esca alt_buf high
        esca term_clear
        esca curs low);
}

static uint32_t read_key(int fd) {
    char c;
    int err = read(fd, &c, 1);
    if (err == -1)
        return KEY_INVALID;
    else if (err == 0)
        return KEY_NULL;

    if (c == KEY_ESC) {
        char seq[3] = {0};
        err = read(fd, seq, 2);
        if (err == -1 || err == 0)
            return KEY_ESC;

        if (seq[0] == '[') {
            switch (seq[1]) {
            case 'A': return KEY_ARROW_UP;
            case 'B': return KEY_ARROW_DOWN;
            case 'C': return KEY_ARROW_RIGHT;
            case 'D': return KEY_ARROW_LEFT;
            }
        }

        // Deal with escape characters we don't care about by
        // just consuming the last character.
        //
        // returning KEY_INVALID, will make sure we keep reading
        // the input instead of bailing (in the outer loop that
        // calls this).
        err = read(fd, &seq[2], 1);
        if (err == -1 || err == 0)
            return KEY_ESC;
        return KEY_INVALID;
    }

    return c;
}

void repaint(void) {
    say(esca curs low);

    // Paint chat buffer
    const uint16_t max_row = height-2;
    for (uint16_t i = 0; i < max_row; ++i) {
        printf(esca "%u" with "%u" jump, max_row-i, 0);
        say(esca clear_line);
        if (num_lines > 0 && i < num_lines) {
            uint16_t line_index = (num_lines-1) - i;
            if (num_lines > max_row)
                line_index -= chat_offset;
            const char *line = (const char *) lines[line_index];
            write(fileno(stdout), line, strlen(line));
        }
    }

    // Paint line separating chat from input
    printf(esca "%u" with "%u" jump, height-1, 0);
    say(fmt(dim));
    for (uint16_t i = 0; i < width; ++i)
        printf("%s", "─");
    say(fmt(plain));

    // Paint input
    printf(esca "%u" with "%u" jump, height, 0);
    say(esca clear_line);
    write(fileno(stdout), buffer, strlen((char *) buffer));

    // Paint cursor
    printf(esca "%u" with "%u" jump, height, input_offset+1);
    say(esca curs high);
}

static inline void insert(char *buffer, uint16_t offset, char c) {
    const size_t len = strlen(buffer);
    assert(offset <= len);
    for (size_t i = len+1; i > offset; --i)
        buffer[i] = buffer[i-1];
    buffer[offset] = c;
}

static inline void delete(char *buffer, uint16_t offset) {
    const size_t len = strlen(buffer);
    assert(offset <= len);
    for (size_t i = (size_t) offset-1; i < len; ++i)
        buffer[i] = buffer[i+1];
}

static mtx_t voice_mutex;
static uint32_t voice_buffer_offset;
static uint8_t voice_buffer[8*192000] = {0};

static int voice_sock;

void data_callback(ma_device *device, void *output, const void *input, ma_uint32 frame_count) {
    size_t size = ma_get_bytes_per_sample(device->playback.format) * device->playback.channels * frame_count;
    if (socket_send_all(voice_sock, input, size) == -1) {
        log_error("voice send() failed: %s", strerror(errno));
        return;
    }

    mtx_lock(&voice_mutex);
    if (voice_buffer_offset >= size) {
        memcpy(output, voice_buffer, size);
        memmove(voice_buffer, voice_buffer+size, voice_buffer_offset-size);
        voice_buffer_offset -= size;
    }
    mtx_unlock(&voice_mutex);
}

int read_int_from_stdin(int *output) {
    char buf[16] = {0};
    if (fgets(buf, 16, stdin) == NULL)
        return 1;
    *output = atoi(buf);
    return 0;
}

void *handle_voice(void *args) {
    (void) args;

    static uint8_t buf[4800];
    while (true) {
        memset(buf, 0, sizeof(buf));
        ssize_t bytes_read = recv(voice_sock, buf, ARRLEN(buf), 0);
        if (bytes_read == -1) {
            log_error("Server disconnected (recv failed)!");
            continue;
        }
        log_info("read %d bytes", bytes_read);

        if (voice_buffer_offset + bytes_read <= ARRLEN(voice_buffer)) {
            mtx_lock(&voice_mutex);
            memcpy(voice_buffer + voice_buffer_offset, buf, bytes_read);
            voice_buffer_offset += bytes_read;
            mtx_unlock(&voice_mutex);
        }
    }
}

int main(int argc, char **argv) {
    if (argc != 4) {
        log_error("Usage: gn-client [nick] [hostname] [port]");
        return 1;
    }

    const char *nick = argv[1];
    const char *host = argv[2];
    const char *port = argv[3];

    // Create UDP socket for voice
    voice_sock = socket_connect(SOCK_DGRAM, host, "9054");
    if (voice_sock == -1) {
        return 1;
    }

    if (mtx_init(&voice_mutex, mtx_plain) == thrd_error) {
        log_info("Failed to create voice mutex");
        return 1;
    }

    thrd_t voice_thread;
    if (thrd_create(&voice_thread, (thrd_start_t) handle_voice, (void *) port) == thrd_error) {
        log_info("Failed to create voice thread");
        return 1;
    }

    // Initialize miniaudio
    ma_context context;
    if (ma_context_init(NULL, 0, NULL, &context) != MA_SUCCESS) {
        fputs("miniaudio: Failed to initialize context", stderr);
        goto return_normal;
    }

    // Get list of playback and capture devices
    ma_device_info* playback_infos = NULL;
    ma_uint32       playback_count = 0;
    ma_device_info* capture_infos = NULL;
    ma_uint32       capture_count = 0;
    if (ma_context_get_devices(&context, &playback_infos, &playback_count, &capture_infos, &capture_count) != MA_SUCCESS) {
        fputs("miniaudio: Failed to get devices", stderr);
        goto context_cleanup;
    }

    // Select input device
    puts("Input devices:");
    for (ma_uint32 i = 0; i < capture_count; ++i) {
        printf("  %d - %s\n", i, capture_infos[i].name);
    }
    printf("Select input device: ");

    int input_choice = 0;
    if (read_int_from_stdin(&input_choice) != 0 || (input_choice < 0 || (ma_uint32) input_choice >= capture_count)) {
        fputs("Give me some reasonable input please (^o.o^)", stderr);
        goto context_cleanup;
    }

    puts("");

    // Select output device
    puts("Output devices:");
    for (ma_uint32 i = 0; i < playback_count; ++i) {
        printf("  %d - %s\n", i, playback_infos[i].name);
    }
    printf("Select output device: ");

    int output_choice = 0;
    if (read_int_from_stdin(&output_choice) != 0 || (output_choice < 0 || (ma_uint32) output_choice >= playback_count)) {
        fputs("Give me some reasonable output please (^o.o^)", stderr);
        goto context_cleanup;
    }

    // Initialize devices
    ma_device_config config   = ma_device_config_init(ma_device_type_duplex);
    config.playback.pDeviceID = &playback_infos[output_choice].id;
    config.playback.format    = ma_format_f32;
    config.playback.channels  = 2;
    config.capture.pDeviceID  = &capture_infos[input_choice].id;
    config.capture.format     = ma_format_f32;
    config.capture.channels   = 2;
    config.sampleRate         = 48000;
    config.dataCallback       = data_callback;
    config.pUserData          = NULL;

    ma_device device;
    if (ma_device_init(&context, &config, &device) != MA_SUCCESS) {
        fputs("miniaudio: Failed to init device", stderr);
        goto device_cleanup;
    }
    device.masterVolumeFactor = 0.5;
    log_info("mastr volume %f", device.masterVolumeFactor);

    // Actually play the input/output
    ma_device_start(&device);
    fgetc(stdin);

    // Create TCP socket for chatting
    int sock = socket_connect(SOCK_STREAM, host, port);
    if (sock == -1) {
        return 1;
    }

    // Setup epoll
    int set = epoll_create1(0);
    if (set == -1) {
        log_error("Failed to create epoll fd: %s", strerror(errno));
        return 1;
    }

    const bool interactive = isatty(fileno(stdin));

    struct epoll_event ev = {
        .events = EPOLLIN | EPOLLET | EPOLLRDHUP,
        .data.fd = sock,
    };

    if (epoll_ctl(set, EPOLL_CTL_ADD, sock, &ev) == -1) {
        log_error("Failed to add new connected fd to epoll: %s!\n", strerror(errno));
        return 1;
    }

    set_blocking(sock, false);

    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = fileno(stdin);
    if (epoll_ctl(set, EPOLL_CTL_ADD, fileno(stdin), &ev) == -1) {
        log_error("Failed to add new connected fd to epoll: %s!\n", strerror(errno));
        return 1;
    }
    set_blocking(fileno(stdin), false);

    bool should_repaint = false;
    bool should_run = true;
    uint8_t *output = chat_buffer;

    if (interactive) {
        initterm();
        signal(SIGWINCH, resize);
        resize(0);
        should_repaint = true;
    }

    struct epoll_event events[64] = {0};
    while (should_run) {
        const int num_events = epoll_wait(set, events, ARRLEN(events), -1);
        if (num_events == -1 && errno != EINTR) {
            log_error("epoll_wait() failed: %s", strerror(errno));
            return 1;
        }

        for (int i = 0; i < num_events; ++i) {
            if (events[i].data.fd == fileno(stdin)) {
                while (should_run) {
                    uint32_t key = read_key(fileno(stdin));
                    if (key == KEY_INVALID)
                        break;

                    switch (key) {
                    case KEY_NULL:
                    case KEY_ESC:
                        should_run = false;
                        break;
                    case KEY_ARROW_LEFT:
                        if (input_offset > 0)
                            input_offset--;
                        break;
                    case KEY_ARROW_RIGHT:
                        if ((size_t) input_offset < strlen((char *) buffer))
                            input_offset++;
                        break;
                    case KEY_ARROW_UP:
                        // Only increase chat offset if the number of lines in the chat
                        // buffer exceed the height of the chatbox AND the offset is
                        // smaller than the maxiumum possible offset.
                        if (num_lines > height-2 && chat_offset < num_lines - (height-2))
                            chat_offset++;
                        break;
                    case KEY_ARROW_DOWN:
                        if (chat_offset > 0)
                            chat_offset--;
                        break;
                    // TODO(anjo): How to handle \n?
                    case '\n':
                    case KEY_ENTER: {
                        if (buffer[0] == '\0')
                            break;

                        struct packet p = {
                            .name = nick,
                            .data = buffer,
                            .data_size = strlen((char *) buffer) + 1,
                        };

                        if (packet_size(&p) > ARRLEN(output_buffer)) {
                            log_error("Dropping packet, size larger than output buffer, and we don't support partial packets!");
                            buffer[0] = '\0';
                            input_offset = 0;
                            break;
                        }

                        packet_encode(&p, output_buffer);
                        buffer[0] = '\0';
                        input_offset = 0;

                        if (socket_send_all(sock, output_buffer, packet_size(&p)) == -1) {
                            log_error("Server disconnected (send failed)!");
                            break;
                        }

                        break;
                    }
                    case KEY_BACKSPACE:
                        if (input_offset > 0)
                            delete((char *) buffer, input_offset--);
                        break;
                    default:
                        if ((size_t) input_offset + 1 < ARRLEN(buffer)) {
                            insert((char *) buffer, input_offset++, (char) key);
                        }
                    }
                }
                should_repaint = true;
            } else if (events[i].events & EPOLLRDHUP) {
                if (epoll_ctl(set, EPOLL_CTL_DEL, events[i].data.fd, NULL) == -1) {
                    log_error("Failed to remove disconnected fd from epoll: %s!\n", strerror(errno));
                    return 1;
                }
                close(events[i].data.fd);
            } else if (events[i].events & EPOLLIN) {
                ssize_t bytes_read = socket_recv_all(events[i].data.fd, output_buffer, ARRLEN(output_buffer));
                if (bytes_read == -1) {
                    log_error("Server disconnected (recv failed)!");
                    break;
                }

                struct packet p = {0};
                ssize_t read_size = 0;
                while (read_size < bytes_read &&
                       packet_decode(output_buffer + read_size, bytes_read, &p) == 0) {
                    const char *begin_fmt = fmt(bright with fg red);
                    const char *end_fmt = fmt(plain);
                    size_t offset = 0;

                    memcpy(output+offset, begin_fmt, strlen(begin_fmt));
                    offset += strlen(begin_fmt);

                    memcpy(output+offset, p.name, strlen(p.name));
                    offset += strlen(p.name);

                    memcpy(output+offset, "> ", 2);
                    offset += 2;

                    memcpy(output+offset, end_fmt, strlen(end_fmt));
                    offset += strlen(end_fmt);

                    memcpy(output+offset, p.data, p.data_size);
                    offset += p.data_size;

                    lines[num_lines++] = output;

                    output += offset;
                    read_size += packet_size(&p);
                    should_repaint = true;
                }
            } else {
                log_error("Unhandled epoll event!");
            }
        }

        if (interactive && should_repaint) {
            repaint();
            should_repaint = false;
        }
    }

    // If we're not interactive, wait a while before exiting so
    // we don't accidentatly exit before everything is sent!
    //
    // TODO(anjo): Instead of doing this, we can
    //     1. turn of blocking,
    //     2. send some EOL packet?!
    //
    if (!interactive)
        usleep(500);

    thrd_join(voice_thread, NULL);
    mtx_destroy(&voice_mutex);

    close(sock);

    ma_device_stop(&device);

device_cleanup:
    ma_device_uninit(&device);
context_cleanup:
    ma_context_uninit(&context);
return_normal:

    return 0;
}
