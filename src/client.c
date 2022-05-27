#include "common/log.h"
#include "common/socket.h"

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

#define ARRLEN(arr) \
    (sizeof(arr)/sizeof(arr[0]))

// TODO(anjo): doesn't this already exist somewhere?
#define STDIN 1

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

struct termios initial;
uint16_t width, height;
char buffer[2048] = {0};

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
    // since atexit has already registered a handler,
    // a call to exit(3) is all we actually need
    exit(1);
}

void repaint(void);

void resize(int i) {
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

    termios: {
        struct termios t;
        tcgetattr(1, &t);
        initial = t;
        t.c_lflag &= (~ECHO & ~ICANON);
        tcsetattr(1, TCSANOW, &t);
    };

    atexit(restore);
    signal(SIGTERM, restore_die);
    signal(SIGINT, restore_die);

    say(esca alt_buf high
        esca term_clear
        esca curs low);
}

void repaint(void) {
    const uint16_t
        mx = (width / 2) - (40 / 2),
           my = (height / 2) + 1;

    //if (help_visible) for (size_t i = 0; i < sz(instructions); ++i)
    //    printf(esca "%u" with "%u" jump fmt(plain) "%s",
    //           // place lines above meter
    //           my - (1 + (sz(instructions) - i)),
    //           // center each line
    //           (width/2) - (textsz(instructions[i])/2),
    //           // print line
    //           instructions[i]);

    printf(esca "%u" with "%u" jump, my, mx);
    say(esca clear_line);

    //for (size_t i = 0; i < meter_size; ++i)
    //    printf(esca wfg "%u" color "%s",
    //           i < meter_value ? meter_color_on : meter_color_off,
    //           i < meter_value ? "█" : "░");
}


int main(int argc, char **argv) {
    if (argc != 3) {
        log_error("Usage: gn-client [hostname] [port]");
        return 1;
    }

    const char *host = argv[1];
    const char *port = argv[2];

    int sock = socket_connect(host, port);
    if (sock == -1) {
        return 1;
    }

    // Setup epoll
    int set = epoll_create1(0);
    if (set == -1) {
        log_error("Failed to create pollset: %s", strerror(errno));
        return 1;
    }

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
    ev.data.fd = STDIN;
    if (epoll_ctl(set, EPOLL_CTL_ADD, STDIN, &ev) == -1) {
        log_error("Failed to add new connected fd to epoll: %s!\n", strerror(errno));
        return 1;
    }
    set_blocking(STDIN, false);

    initterm();
    signal(SIGWINCH, resize);
    resize(0);

    bool should_run = true;
    char *input = buffer;
    unsigned char buf[256] = {0};

    struct epoll_event events[64] = {0};
    while (should_run) {
        const int num_events = epoll_wait(set, events, ARRLEN(events), -1);
        if (num_events == -1) {
            log_error("epoll_wait() failed: %s", strerror(errno));
            return 1;
        }

        for (int i = 0; i < num_events; ++i) {
            if (events[i].data.fd == STDIN) {
                // TODO(anjo): Move to EPOLLIN?
                char inkey = '\0';
                while (inkey != '\x1b') {
                    if (read(STDIN, &inkey, 1) == -1)
                        break;

                    switch (inkey) {
                    case '\r':
                    case '\n': {
                        // Send data to server, use `strlen(buf)-1` to remove trailing
                        // newline added by `fgets`.
                        if (socket_send_all(sock, buffer, strlen(buffer)) == -1) {
                            log_error("Server disconnected!");
                            break;
                        }


                        input = buffer;
                        *input = '\0';
                        break;
                    }
                    case 127:
                    case '\b':
                        if (input > buffer)
                            *(--input) = '\0';
                        break;
                    default:
                        if (input + 1 < buffer + ARRLEN(buffer)) {
                            *input++ = inkey;
                            *input   = '\0';
                        }
                    }

                }
                repaint();
                puts(buffer);
            } else if (events[i].events & EPOLLRDHUP) {
                if (epoll_ctl(set, EPOLL_CTL_DEL, events[i].data.fd, NULL) == -1) {
                    log_error("Failed to remove disconnected fd from epoll: %s!\n", strerror(errno));
                    return 1;
                }
                close(events[i].data.fd);
            } else if (events[i].events & EPOLLIN) {
                memset(buf, 0, sizeof(buf));
                if (socket_recv_all(events[i].data.fd, buf, sizeof(buf)-1) == -1) {
                    log_error("Server disconnected!");
                    break;
                }
                printf("> %s\n", buf);
            } else {
                log_error("Unhandled epoll event!");
            }
        }
    }

    //char inkey = '\0';
    //while (inkey != '\x1b') {
    //    read(1, &inkey, 1);

    //    switch (inkey) {
    //    case '\r':
    //    case '\n': {
    //        // Send data to server, use `strlen(buf)-1` to remove trailing
    //        // newline added by `fgets`.
    //        if (socket_send_all(sock, buffer, strlen(buffer)) == -1) {
    //            log_error("Server disconnected!");
    //            break;
    //        }

    //        // Assume the server sends back data, so we recieve it here
    //        // (blocking).
    //        memset(buf, 0, sizeof(buf));
    //        if (socket_recv_all(sock, buf, sizeof(buf)-1) == -1) {
    //            log_error("Server disconnected!");
    //            break;
    //        }
    //        printf("> %s\n", buf);
    //        input = buffer;
    //        *input = '\0';
    //        break;
    //    }
    //    case 127:
    //    case '\b':
    //        if (input > buffer)
    //            *(--input) = '\0';
    //        break;
    //    default:
    //        if (input + 1 < buffer + ARRLEN(buffer)) {
    //            *input++ = inkey;
    //            *input   = '\0';
    //        }
    //    }

    //    repaint();
    //    puts(buffer);

    //}

    close(sock);

    return 0;
}
