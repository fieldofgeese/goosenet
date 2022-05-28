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
    for (uint16_t i = 0; i < MIN(height-2, num_lines); ++i) {
        const char *line = (const char *) lines[num_lines-i-1];
        printf(esca "%u" with "%u" jump, height-2-i, 0);
        say(esca clear_line);
        puts(line);
    }

    printf(esca "%u" with "%u" jump, height-1, 0);
    say(esca clear_line);
    printf("(%lu) %s", strlen((char *) buffer), (char *) buffer);
    say(esca curs high);
}


int main(int argc, char **argv) {
    if (argc != 4) {
        log_error("Usage: gn-client [nick] [hostname] [port]");
        return 1;
    }

    const char *nick = argv[1];
    const char *host = argv[2];
    const char *port = argv[3];

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
    uint8_t *input = buffer;
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
                    case KEY_ARROW_RIGHT:
                    case KEY_ARROW_UP:
                    case KEY_ARROW_DOWN:
                        if (input + 1 < buffer + ARRLEN(buffer)) {
                            *input++ = (char) '^';
                            *input   = '\0';
                        }
                        break;
                    // TODO(anjo): How to handle \n?
                    case '\n':
                    case KEY_ENTER: {
                        if (input == buffer)
                            break;

                        struct packet p = {
                            .name = nick,
                            .data = buffer,
                            .data_size = strlen((char *) buffer) + 1,
                        };

                        if (packet_size(&p) > ARRLEN(output_buffer)) {
                            log_error("Dropping packet, size larger than output buffer, and we don't support partial packets!");
                            input = buffer;
                            *input = '\0';
                            break;
                        }

                        packet_encode(&p, output_buffer);
                        input = buffer;
                        *input = '\0';

                        if (socket_send_all(sock, output_buffer, packet_size(&p)) == -1) {
                            log_error("Server disconnected (send failed)!");
                            break;
                        }

                        break;
                    }
                    case KEY_BACKSPACE:
                        if (input > buffer)
                            *(--input) = '\0';
                        break;
                    default:
                        if (input + 1 < buffer + ARRLEN(buffer)) {
                            *input++ = (char) key;
                            *input   = '\0';
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
                    memcpy(output, p.name, strlen(p.name));
                    memcpy(output + strlen(p.name), "> ", 2);
                    memcpy(output + strlen(p.name) + 2, p.data, p.data_size);
                    lines[num_lines++] = output;

                    output += strlen(p.name) + 2 + p.data_size;
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

    close(sock);

    return 0;
}
