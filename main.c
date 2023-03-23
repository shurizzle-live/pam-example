#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux
#include <sys/epoll.h>
#include <sys/timerfd.h>
#elif __APPLE__
#include <sys/select.h>
#else
#error "unsupported platform"
#endif

struct Buffer {
  size_t len;
  size_t cap;
  char *data;
};

inline static struct Buffer buffer_new() { return (struct Buffer){0, 0, NULL}; }

static void buffer_push_char(struct Buffer *buf, char c) {
  if (!buf->data) {
    buf->len = 0;
    buf->cap = 10;
    buf->data = malloc(10);
  }

  if (buf->len == buf->cap) {
    buf->cap += 10;
    buf->data = realloc(buf->data, buf->cap);
  }

  buf->data[buf->len++] = c;
}

static void buffer_shrink_to_fit(struct Buffer *buf) {
  if (buf->len != buf->cap && buf->data) {
    buf->cap = buf->len;
    buf->data = realloc(buf->data, buf->cap);
  }
}

static char *buffer_to_string(struct Buffer *buf) {
  buffer_push_char(buf, '\0');
  buffer_shrink_to_fit(buf);
  char *res = buf->data;
  buf->data = NULL;
  buf->len = buf->cap = 0;
  return res;
}

static void buffer_destroy(struct Buffer *buf) {
  if (buf->data) {
    free(buf->data);
    buf->data = NULL;
  }
  buf->len = buf->cap = 0;
}

#ifdef __linux
char *readline(FILE *fp, time_t timeout) {
  char *res = NULL;
  int tfd = -1;
  int efd = -1;
  struct Buffer buf = buffer_new();

  int flags = 0;
  {
    int f = fcntl(fileno(fp), F_GETFL);
    if (f < 0) {
      return res;
    }
    if (!(f & O_NONBLOCK)) {
      if (fcntl(fileno(fp), F_SETFL, f | O_NONBLOCK) < 0) {
        goto err;
      }
      flags = f;
    }
  }

  if ((tfd = timerfd_create(CLOCK_BOOTTIME, TFD_NONBLOCK | TFD_CLOEXEC)) < 0) {
    goto err;
  }

  {
    struct itimerspec spec = {{0, 0}, {timeout, 0}};
    if (timerfd_settime(tfd, 0, &spec, NULL) < 0) {
      goto err;
    }
  }

  if ((efd = epoll_create1(EPOLL_CLOEXEC)) < 0) {
    goto err;
  }

  {
    struct epoll_event ev = {EPOLLIN, {.fd = tfd}};
    if (epoll_ctl(efd, EPOLL_CTL_ADD, tfd, &ev) < 0) {
      goto err;
    }
  }

  {
    struct epoll_event ev = {EPOLLIN, {.fd = fileno(fp)}};
    if (epoll_ctl(efd, EPOLL_CTL_ADD, fileno(fp), &ev) < 0) {
      goto err;
    }
  }

  for (;;) {
    struct epoll_event ev;
    int err;
    while ((err = epoll_wait(efd, &ev, 1, -1)) < 0 && errno == EINTR)
      ;

    if (ev.data.fd == tfd) {
      putchar('\n');
      errno = ETIMEDOUT;
      goto err;
    } else if (ev.data.fd == fileno(fp)) {
      bool cont;
      do {
        int ch;
        cont = false;
        while ((ch = fgetc(fp)) < 0 && ch != EOF && errno == EINTR)
          ;

        if (ch < 0) {
          if (ch == EOF) {
            putchar('\n');
            res = buffer_to_string(&buf);
            goto end;
          } else if (errno != EAGAIN) {
            goto err;
          }
        } else {
          char c = ch;

          if (c == '\n') {
            if (buf.data[buf.len - 1] == '\r') {
              --buf.len;
            }
            res = buffer_to_string(&buf);
            goto end;
          } else if (c == '\x15') {
            memset(buf.data, 0, buf.len);
            buf.len = 0;
            cont = true;
          } else {
            buffer_push_char(&buf, c);
            cont = true;
          }
        }
      } while (cont);
    }
  }

  goto end;
err:
end : {
  int backup_errno = errno;

  if (flags) {
    fcntl(fileno(fp), flags);
  }

  if (tfd >= 0) {
    close(tfd);
  }

  if (efd >= 0) {
    close(efd);
  }

  buffer_destroy(&buf);

  errno = backup_errno;
}
  return res;
}
#elif __APPLE__
char *readline(FILE *fp, time_t timeout) {
  char *res = NULL;
  struct Buffer buf = buffer_new();

  int flags = 0;
  {
    int f = fcntl(fileno(fp), F_GETFL);
    if (f == -1) {
      return res;
    }
    if (!(f & O_NONBLOCK)) {
      if (fcntl(fileno(fp), F_SETFL, f | O_NONBLOCK) == -1) {
        goto err;
      }
      flags = f;
    }
  }

  fd_set fds;
  FD_ZERO(&fds);
  for (;;) {
    struct timeval timeout_val = {timeout, 0};
    FD_SET(fileno(fp), &fds);

    {
      int err;
      while ((err = select(fileno(fp) + 1, &fds, NULL, NULL, &timeout_val)) ==
                 -1 &&
             errno == EINTR)
        ;
      if (err == 0) {
        errno = ETIMEDOUT;
        goto err;
      } else if (err == -1) {
        goto err;
      }
    }

    bool cont;
    do {
      int ch;
      cont = false;
      while ((ch = fgetc(fp)) == -1 && ferror(fp) && errno == EINTR)
        ;

      if (ch == -1) {
        if (ferror(fp)) {
          if (errno != EAGAIN) {
            goto err;
          }
        } else {
          putchar('\n');
          res = buffer_to_string(&buf);
          goto end;
        }
      } else {
        char c = ch;

        if (c == '\n') {
          if (buf.data[buf.len - 1] == '\r') {
            --buf.len;
          }
          res = buffer_to_string(&buf);
          goto end;
        } else if (c == '\x15') {
          memset(buf.data, 0, buf.len);
          buf.len = 0;
          cont = true;
        } else {
          buffer_push_char(&buf, c);
          cont = true;
        }
      }
    } while (cont);
  }

  goto end;
err:
end : {
  int backup_errno = errno;

  if (flags) {
    fcntl(fileno(fp), flags);
  }

  buffer_destroy(&buf);

  errno = backup_errno;
}
  return res;
}
#endif

char *readline_noecho(FILE *fp, time_t timeout) {
  char *res = NULL;

  struct termios stat;
  if (tcgetattr(fileno(fp), &stat) < 0) {
    return res;
  }

  {
    struct termios new_stat = stat;
    new_stat.c_iflag = IGNBRK | BRKINT | INLCR | ICRNL;
    new_stat.c_lflag = ISIG | ICANON | ECHOE | ECHOK | ECHONL | IEXTEN;
    if (tcsetattr(fileno(fp), TCSANOW, &new_stat) < 0) {
      return res;
    }
  }

  res = readline(fp, timeout);

  goto end;
err:
end : {
  int backup_errno = errno;
  tcsetattr(fileno(fp), TCSANOW, &stat);
  errno = backup_errno;
}
  return res;
}

#define TIMEOUT 600

int conversation(int num_msgs, const struct pam_message **msgs,
                 struct pam_response **resps, void *data) {
  *resps = malloc(sizeof(struct pam_response) * num_msgs);

  for (size_t i = 0; i < num_msgs; i++) {
    const struct pam_message *msg = &((*msgs)[i]);
    struct pam_response *res = &((*resps)[i]);

    switch (msg->msg_style) {
    case PAM_PROMPT_ECHO_ON: {
      printf("%s ", msg->msg);
      fflush(stdout);
      char *line = readline(stdin, TIMEOUT);
      if (line) {
        res->resp = line;
        res->resp_retcode = PAM_SUCCESS;
      } else {
        putchar('\n');
        res->resp = NULL;
        res->resp_retcode = PAM_CONV_ERR;
      }
      break;
    }
    case PAM_PROMPT_ECHO_OFF: {
      printf("%s", msg->msg);
      fflush(stdout);
      char *line = readline_noecho(stdin, TIMEOUT);
      if (line) {
        res->resp = line;
        res->resp_retcode = PAM_SUCCESS;
      } else {
        putchar('\n');
        res->resp = NULL;
        res->resp_retcode = PAM_CONV_ERR;
      }
      break;
    }
    case PAM_ERROR_MSG:
      fprintf(stderr, "%s\n", msg->msg);
      res->resp = NULL;
      res->resp_retcode = PAM_SUCCESS;
      break;
    case PAM_TEXT_INFO:
      printf("%s\n", msg->msg);
      res->resp = NULL;
      res->resp_retcode = PAM_SUCCESS;
      break;
    default:
      res->resp = NULL;
      res->resp_retcode = PAM_CONV_ERR;
      break;
    }
  }

  return PAM_SUCCESS;
}

int main(void) {
  pam_handle_t *pamh;
  char *username = NULL;

  {
    int uid = getuid();
    errno = 0;
    struct passwd *pw = getpwuid(uid);
    if (!pw) {
      if (errno) {
        fprintf(stderr, "%s\n", strerror(errno));
      } else {
        fprintf(stderr, "User with uid %d not found\n", uid);
      }
      return 1;
    }

    username = strdup(pw->pw_name);
  }

  printf("Hi, %s!\n", username);

  struct pam_conv conv = {conversation, NULL};

  int err;
  if ((err = pam_start("sudo", username, &conv, &pamh)) != PAM_SUCCESS) {
    fprintf(stderr, "%s\n", pam_strerror(pamh, err));
    return 1;
  }

  int ret = 0;

  if ((err = pam_authenticate(pamh, PAM_DISALLOW_NULL_AUTHTOK)) !=
      PAM_SUCCESS) {
    fprintf(stderr, "%s\n", pam_strerror(pamh, err));
    ret = 1;
    goto end;
  }

  // TODO: stuff

end:
  pam_end(pamh, err);

  if (username) {
    free(username);
  }

  return ret;
}
