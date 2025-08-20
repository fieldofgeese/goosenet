#include "common/common.h"
#include "common/log.h"
#include "common/socket.h"
#include "common/packet.h"
#include "common/net-protocol.h"
#include "common/stack.h"
#include "crypto.h"

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
uint8_t buffer[INPUT_BUFFER_SIZE] = {0};
uint8_t chat_buffer[CHAT_BUFFER_SIZE] = {0};

uint16_t line_offset = 0;
uint8_t *lines[NUM_CHAT_LINES] = {0};
uint16_t line_lens[NUM_CHAT_LINES] = {0};
uint32_t num_lines = 0;
static FILE *fd;

bool show_log = true;

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

#include <errno.h>

void repaint(void) {
    fseek(fd, 0, SEEK_END);
    long size = ftell(fd);
    fseek(fd, 0, SEEK_SET);
    uint8_t *mem = malloc(size+1);
    size_t read = fread(mem, 1, size, fd);
    printf("read: %ld\n", read);
    printf("errno: %s\n", strerror(errno));
    printf("size: %ld\n", size);
    mem[size] = 0;
    printf("mem %s", mem);
    assert(read == size);

    num_lines = 0;
    uint8_t *l = mem;
    for (long i = 0; i < size; ++i) {
        if (mem[i] == '\n') {
            lines[num_lines] = l;
            line_lens[num_lines] = mem+i - l;
            ++num_lines;
            l = mem + i+1;
        }
    }

    say(esca curs low);

    // Paint chat buffer
    const uint16_t max_row = height-2;
    const uint32_t max_line_offset = num_lines - max_row;
    if (line_offset > max_line_offset) {
        line_offset = max_line_offset;
    }
    for (uint16_t i = 0; i < max_row; ++i) {
        printf(esca "%u" with "%u" jump, max_row-i, 0);
        say(esca clear_line);
        if (num_lines > 0 && i < num_lines) {
            uint16_t line_index = (num_lines-1) - i;
            if (num_lines > max_row) {
                line_index -= line_offset;
            }
            const char *line = (const char *) lines[line_index];
            write(fileno(stdout), line, line_lens[line_index]);
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

    free(mem);
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

int main(int argc, char **argv) {
    const size_t pagesize = 4096;
    struct stack stack = {
        .size = pagesize,
    };

    const char *io_path = "io-client";
    FILE *fd_global = NULL;
    FILE *fd_log = fopen(stack_fmt(&stack, "%s/log", io_path), "w+");

    assert(fd_log);
    fd = fd_log;
    log_init(fd_log, false);

    if (argc != 4) {
        log_error("Usage: gn-client [nick] [hostname] [port]");
        return 1;
    }

    const char *nick = argv[1];
    const char *host = argv[2];
    const char *port = argv[3];

    crypto_init("keys-client", "password");
    crypto_generate_or_load_keypair(&stack, nick, KEYPAIR_USER);

    int sock = socket_connect(host, port);
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

    enum connection_state state = HANDSHAKE_WAIT_SERVER_PUB;
    uint8_t *server_pub_key_data;
    size_t server_pub_key_len;

    struct epoll_event events[64] = {0};
    while (should_run) {
        stack_clear(&stack);

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
                        if (num_lines > height-2 && line_offset < num_lines - (height-2)) {
                            ++line_offset;
                        }
                        break;
                    case KEY_ARROW_DOWN:
                        if (line_offset > 0)
                            --line_offset;
                        break;
                    // TODO(anjo): How to handle \n?
                    case '\n':
                    case KEY_ENTER: {
                        if (buffer[0] == '\0') {
                            break;
                        }

                        uint8_t *encrypted;
                        size_t encrypted_len;
                        crypto_encrypt(&stack, "session", KEYPAIR_SESSION, buffer, strlen((char *) buffer) + 1, &encrypted, &encrypted_len);

                        struct packet p = {
                            .name = nick,
                            .data = encrypted,
                            .data_size = encrypted_len,
                        };

                        if (packet_size(&p) > stack.size - stack.top) {
                            log_error("Dropping packet, size larger than output buffer, and we don't support partial packets!");
                            buffer[0] = '\0';
                            input_offset = 0;
                            break;
                        }

                        const uint8_t *output = packet_encode(&stack, &p);
                        buffer[0] = '\0';
                        input_offset = 0;

                        if (socket_send_all(sock, output, packet_size(&p)) == -1) {
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
                uint8_t *input;
                ssize_t bytes_read = socket_recv_all(&stack, events[i].data.fd, &input);
                if (bytes_read == -1) {
                    log_error("Server disconnected (recv failed)!");
                    break;
                }

                struct packet p = {0};
                ssize_t read_size = 0;
                while (read_size < bytes_read &&
                       packet_decode(input + read_size, bytes_read, &p) == 0) {
                    read_size += packet_size(&p);
                    if (state == CONNECTED) {
                        const char *begin_fmt = fmt(bright with fg red);
                        const char *end_fmt = fmt(plain);
                        size_t offset = 0;

                        uint8_t *decrypted;
                        size_t decrypted_len;
                        crypto_decrypt(&stack, p.data, p.data_size, &decrypted, &decrypted_len);

                        memcpy(output+offset, begin_fmt, strlen(begin_fmt));
                        offset += strlen(begin_fmt);

                        memcpy(output+offset, p.name, strlen(p.name));
                        offset += strlen(p.name);

                        memcpy(output+offset, "> ", 2);
                        offset += 2;

                        memcpy(output+offset, end_fmt, strlen(end_fmt));
                        offset += strlen(end_fmt);

                        memcpy(output+offset, decrypted, decrypted_len);
                        offset += p.data_size;

                        memcpy(output+offset, "\n", 1);
                        offset += 1;

                        fwrite(output, 1, offset, fd_global);

                        output += offset;
                        should_repaint = true;
                    } else {
                        switch (state) {
                            case HANDSHAKE_WAIT_SERVER_PUB: {
                                log_info("received public key len: %d", p.data_size);

                                crypto_add_key(&stack, p.data, p.data_size, KEY_PUBLIC);

                                size_t pub_len;
                                const uint8_t *pub_key = crypto_get_key(&stack, nick, KEYPAIR_USER, KEY_PUBLIC, &pub_len);

                                uint8_t *out;
                                size_t out_len;
                                crypto_encrypt(&stack, "server", KEYPAIR_SERVER, pub_key, pub_len, &out, &out_len);

                                log_info("  [handshake] sending encrypted public key: %lu", out_len);

                                struct packet p = {
                                    .name = nick,
                                    .data = out,
                                    .data_size = out_len
                                };
                                const uint8_t *output = packet_encode(&stack, &p);
                                if (socket_send_all(sock, output, packet_size(&p)) == -1) {
                                    log_error("Failed to send public key (send failed)!");
                                    break;
                                }

                                state = HANDSHAKE_CHALLENGE;
                                break;
                            }
                            case HANDSHAKE_CHALLENGE: {
                                log_info("received challenge key len: %d", p.data_size);

                                uint8_t *challenge;
                                size_t challenge_len;
                                crypto_decrypt(&stack, p.data, p.data_size, &challenge, &challenge_len);

                                log_info("Received challenge: %.*s", (int) challenge_len, challenge);

                                uint8_t *encrypted;
                                size_t encrypted_len;
                                crypto_encrypt(&stack, "server", KEYPAIR_SERVER, challenge, challenge_len, &encrypted, &encrypted_len);

                                struct packet p = {
                                    .name = nick,
                                    .data = encrypted,
                                    .data_size = encrypted_len,
                                };
                                const uint8_t *output = packet_encode(&stack, &p);
                                if (socket_send_all(sock, output, packet_size(&p)) == -1) {
                                    log_error("Failed to send challenge response (send failed)!");
                                    break;
                                }
                                state = HANDSHAKE_WAIT_SESSION_KEYS;
                                break;
                            }
                            case HANDSHAKE_WAIT_SESSION_KEYS: {
                                log_info("received session keys len: %d", p.data_size);

                                uint8_t *decrypted;
                                size_t decrypted_len;
                                crypto_decrypt(&stack, p.data, p.data_size, &decrypted, &decrypted_len);

                                uint32_t session_pub_len = ntohl(pop_value(&decrypted, uint32_t));
                                uint32_t session_prv_len = ntohl(pop_value(&decrypted, uint32_t));
                                uint8_t *session_pub = pop_bytes(&decrypted, session_pub_len);
                                uint8_t *session_prv = pop_bytes(&decrypted, session_prv_len);

                                crypto_add_key(&stack, session_pub, session_pub_len, KEY_PUBLIC);
                                crypto_add_key(&stack, session_prv, session_prv_len, KEY_PRIVATE);

                                fd_global = fopen(stack_fmt(&stack, "%s/global", io_path), "w+");
                                setvbuf(fd_global, NULL, _IONBF, 0);
                                fd = fd_global;

                                state = CONNECTED;
                                break;
                            }
                            default:
                                log_error("Unexpected connection state during handshake");
                                return 1;
                        }
                    }
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

    crypto_deinit();
    stack_deinit(&stack);

    fclose(fd_log);
    if (fd_global) {
        fclose(fd_global);
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

    close(sock);

    return 0;
}
