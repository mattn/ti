/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Tail queue declarations.
 */
#define TAILQ_HEAD(name, type)                                          \
struct name {                                                           \
        struct type *tqh_first; /* first element */                     \
        struct type **tqh_last; /* addr of last next element */         \
}

#define TAILQ_HEAD_INITIALIZER(head)                                    \
        { NULL, &(head).tqh_first }

#define TAILQ_ENTRY(type)                                               \
struct {                                                                \
        struct type *tqe_next;  /* next element */                      \
        struct type **tqe_prev; /* address of previous next element */  \
}

/*
 * Tail queue functions.
 */
#define TAILQ_CONCAT(head1, head2, field) do {                          \
        if (!TAILQ_EMPTY(head2)) {                                      \
                *(head1)->tqh_last = (head2)->tqh_first;                \
                (head2)->tqh_first->field.tqe_prev = (head1)->tqh_last; \
                (head1)->tqh_last = (head2)->tqh_last;                  \
                TAILQ_INIT((head2));                                    \
        }                                                               \
} while (0)

#define TAILQ_EMPTY(head)       ((head)->tqh_first == NULL)

#define TAILQ_FIRST(head)       ((head)->tqh_first)

#define TAILQ_FOREACH(var, head, field)                                 \
        for ((var) = TAILQ_FIRST((head));                               \
            (var);                                                      \
            (var) = TAILQ_NEXT((var), field))

#define TAILQ_FOREACH_REVERSE(var, head, headname, field)               \
        for ((var) = TAILQ_LAST((head), headname);                      \
            (var);                                                      \
            (var) = TAILQ_PREV((var), headname, field))

#define TAILQ_INIT(head) do {                                           \
        TAILQ_FIRST((head)) = NULL;                                     \
        (head)->tqh_last = &TAILQ_FIRST((head));                        \
} while (0)

#define TAILQ_INSERT_AFTER(head, listelm, elm, field) do {              \
        if ((TAILQ_NEXT((elm), field) = TAILQ_NEXT((listelm), field)) != NULL)\
                TAILQ_NEXT((elm), field)->field.tqe_prev =              \
                    &TAILQ_NEXT((elm), field);                          \
        else {                                                          \
                (head)->tqh_last = &TAILQ_NEXT((elm), field);           \
        }                                                               \
        TAILQ_NEXT((listelm), field) = (elm);                           \
        (elm)->field.tqe_prev = &TAILQ_NEXT((listelm), field);          \
} while (0)

#define TAILQ_INSERT_BEFORE(listelm, elm, field) do {                   \
        (elm)->field.tqe_prev = (listelm)->field.tqe_prev;              \
        TAILQ_NEXT((elm), field) = (listelm);                           \
        *(listelm)->field.tqe_prev = (elm);                             \
        (listelm)->field.tqe_prev = &TAILQ_NEXT((elm), field);          \
} while (0)

#define TAILQ_INSERT_HEAD(head, elm, field) do {                        \
        if ((TAILQ_NEXT((elm), field) = TAILQ_FIRST((head))) != NULL)   \
                TAILQ_FIRST((head))->field.tqe_prev =                   \
                    &TAILQ_NEXT((elm), field);                          \
        else                                                            \
                (head)->tqh_last = &TAILQ_NEXT((elm), field);           \
        TAILQ_FIRST((head)) = (elm);                                    \
        (elm)->field.tqe_prev = &TAILQ_FIRST((head));                   \
} while (0)

#define TAILQ_INSERT_TAIL(head, elm, field) do {                        \
        TAILQ_NEXT((elm), field) = NULL;                                \
        (elm)->field.tqe_prev = (head)->tqh_last;                       \
        *(head)->tqh_last = (elm);                                      \
        (head)->tqh_last = &TAILQ_NEXT((elm), field);                   \
} while (0)

#define TAILQ_LAST(head, headname)                                      \
        (*(((struct headname *)((head)->tqh_last))->tqh_last))

#define TAILQ_NEXT(elm, field) ((elm)->field.tqe_next)

#define TAILQ_PREV(elm, headname, field)                                \
        (*(((struct headname *)((elm)->field.tqe_prev))->tqh_last))

#define TAILQ_REMOVE(head, elm, field) do {                             \
        if ((TAILQ_NEXT((elm), field)) != NULL)                         \
                TAILQ_NEXT((elm), field)->field.tqe_prev =              \
                    (elm)->field.tqe_prev;                              \
        else {                                                          \
                (head)->tqh_last = (elm)->field.tqe_prev;               \
        }                                                               \
        *(elm)->field.tqe_prev = TAILQ_NEXT((elm), field);              \
} while (0)

#define S_IWUSR _S_IWUSR
#define O_NONBLOCK (0)
#undef mkdir
#define mkdir(d,m) mkdir(d)
#define sleep(t) _sleep(t)

size_t strlcpy(char *dest, const char *src, size_t size) {
  size_t ret = strlen(src);
  if (size) {
    size_t len = (ret >= size) ? size - 1 : ret;
    memcpy(dest, src, len);
    dest[len] = '\0';
  }
  return ret;
}
size_t strlcat(char* dest, const char* src, size_t size) {
  char *pdest = dest;
  const char *psrc = src;
  size_t ncopy = size;
  size_t destlen;

  while (*pdest != '\0' && ncopy-- != 0) pdest++;
  destlen = pdest - dest;
  ncopy = size - destlen;
  if (ncopy == 0) return(destlen + strlen(psrc));
  while (*psrc != '\0') {
    if (ncopy != 1) {
      *pdest++ = *psrc;
      ncopy--;
    }
    psrc++;
  }
  *pdest = '\0';
  return(destlen + (psrc - src));
}
int asprintf(char **buffer, char *fmt, ...) {
  int size = 200;
  int nchars;
  va_list ap;
    
  *buffer = (char*) malloc(size);
  if (*buffer == NULL) return -1;
  va_start(ap, fmt);
  nchars = _vsnprintf(*buffer, size, fmt, ap);
  va_end(ap);

  if (nchars >= size) {
    char *tmpbuff;
    size = nchars+1;
    tmpbuff = (char*)realloc(*buffer, size);
    if (tmpbuff == NULL) {
      free(*buffer);
      return -1;
    }
    *buffer=tmpbuff;
    va_start(ap, fmt);
    nchars = vsnprintf(*buffer, size, fmt, ap);
    va_end(ap);
  }
  if (nchars < 0) return nchars;
  return size;
}
char *getpass(const char *prompt) {
  static char buf[128];
  size_t i;

  fputs(prompt, stderr);
  fflush(stderr);
  for (i = 0; i < sizeof(buf) - 1; i++) {
    buf[i] = _getch();
    if (buf[i] == '\r')
      break;
  }
  buf[i] = 0;
  fputs("\n", stderr);
  return buf;
}
long long
strtonum(const char *str, long long min_val, long long max_val, const char **perr) {
  long long ll = 0;
  char *ep;
  *perr = NULL;
  ll = strtoll(str, &ep, 10);
  if (str == ep || *ep != '\0') *perr = "invalid";
  else if (ll < min_val) *perr = "too small";
  else if (ll > max_val) *perr = "too large";
  if (*perr) ll = 0;
  return (ll);
}
int
mkfifo(const char* path, int mask) {
  int fd = open(path, O_RDWR | O_CREAT, mask);
  if (fd != 0) close(fd);
  return fd;
}
