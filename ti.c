/*
 * Copyright (c) 2004 Iwata <iwata@quasiquote.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <getopt.h>
#ifndef _WIN32
#include <pwd.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#else
#include <stdarg.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/param.h>
#include "bsd_compat.h"
#endif

#include <expat.h>
#include <curl/curl.h>
#include <curl/types.h>
#include <curl/easy.h>

#define TI_FRIEND_URL   "https://twitter.com/statuses/friends_timeline"
#define TI_PUBLIC_URL   "https://twitter.com/statuses/public_timeline.xml"
#define TI_USER_URL     "https://twitter.com/statuses/user_timeline"
#define TI_FAVORATE_URL "https://twitter.com/favorites/create"
#define TI_UPDATE_URL   "https://twitter.com/statuses/update.xml"

#define TI_PASSWD_LEN 128

struct ti_entry {
	char *id;
	char *screen_name;
	char *text;

	TAILQ_ENTRY(ti_entry) ti_entries;
};
typedef TAILQ_HEAD(ti_tailhead, ti_entry) ti_head;

enum ti_type { unknown, id, screen_name, text };

typedef struct {
	ti_head *head;
	struct ti_entry *ent;
	int depth;
	enum ti_type type;
} ti_ctx;

typedef struct {
	char *prefix;
	int input;
	int log;
} ti_fds;

static void *
ti_xmalloc(size_t size)
{
	void *ptr = malloc(size);
	if (ptr)
		return ptr;
	abort();
}

static void *
ti_xrealloc(void *ptr, size_t size)
{
	void *new_ptr;

	if (ptr) {
		if ((new_ptr = realloc(ptr, size)) == NULL) {
			free(ptr);
			abort();
		}
		return new_ptr;
	} else
		return ti_xmalloc(size);
}

static void *
ti_xcalloc(size_t nmemb, size_t size)
{
	void *ptr = calloc(nmemb, size);

	if (ptr)
		return ptr;
	else
		abort();
}

static int
ti_valid_msg(struct ti_entry *ent)
{
	return ent->id && ent->screen_name && ent->text;
}

static void
ti_element_start_cb(void *userData, const XML_Char *name, const XML_Char *atts[])
{
	ti_ctx *ctx = userData;

	/* printf("[ELEMENT] %s Start! depth %d\n", name, ctx->depth); */

	if (strcmp(name, "statuses") == 0 && ctx->depth == 0)
		ctx->depth = 1;
	if (strcmp(name, "status") == 0 && ctx->depth == 1) {
		ctx->depth = 2;
		ctx->ent = ti_xcalloc(1, sizeof(*ctx->ent));
	}
	if (strcmp(name, "id") == 0 && ctx->depth == 2)
		ctx->type = id;
	if (strcmp(name, "text") == 0 && ctx->depth == 2)
		ctx->type = text;

	if (strcmp(name, "user") == 0 && ctx->depth == 2)
		ctx->depth = 3;
	if (strcmp(name, "screen_name") == 0 && ctx->depth == 3)
		ctx->type = screen_name;
}

static void
ti_element_end_cb(void *userData, const XML_Char *name)
{
	ti_ctx *ctx = userData;

	/* printf("[ELEMENT] %s End! depth %d\n", name, ctx->depth); */

	if (strcmp(name, "statuses") == 0 && ctx->depth == 1)
		ctx->depth = 0;
	if (strcmp(name, "status") == 0 && ctx->depth == 2) {
		ctx->depth = 1;
		if (ti_valid_msg(ctx->ent))
			TAILQ_INSERT_HEAD(ctx->head, ctx->ent, ti_entries);
	}
	if (strcmp(name, "user") == 0 && ctx->depth == 3)
		ctx->depth = 2;

	ctx->type = unknown;
}

static int
ti_strappend(char **dest, char *append)
{
	if (*dest) {
		size_t len = strlen(*dest) + strlen(append) + 1;

		*dest = ti_xrealloc(*dest, len);
		strlcat(*dest, append, len);
	} else {
		*dest = strdup(append);
	}
	return 1;
}

static void
ti_characterdata_cb(void *userData, const XML_Char *s, int len)
{
	ti_ctx *ctx = userData;
	char *str;

	str = ti_xmalloc(len + 1);
	memcpy(str, s, len);
	str[len] = '\0';

	/* printf("[DATA] %s\n", str); */

	if (ctx->type == id)
		ti_strappend(&ctx->ent->id, str);
	if (ctx->type == text)
		ti_strappend(&ctx->ent->text, str);
	if (ctx->type == screen_name)
		ti_strappend(&ctx->ent->screen_name, str);

	free(str);
}

static int
ti_write_entry(ti_head *head, ti_fds *fds)
{
	struct ti_entry *np;

	TAILQ_FOREACH(np, head, ti_entries) {
		char path[MAXPATHLEN];
		char msg[1024];
		int out;

		snprintf(path, sizeof(path), "%s/out", fds->prefix);
		if ((out = open(path, O_WRONLY | O_APPEND, S_IWUSR)) == -1) {
			perror("open");
			exit(EXIT_FAILURE);
		}
		snprintf(msg, sizeof(msg), "%s: %s\n", np->screen_name, np->text);
		write(out, msg, strlen(msg));
		close(out);

		write(fds->log, msg, strlen(msg));
	}

	return 1;
}

static void
ti_free_entry(ti_head *head)
{
	struct ti_entry *np;

	while ((np = TAILQ_FIRST(head)) != NULL) {
		TAILQ_REMOVE(head, np, ti_entries);
		free(np->id);
		free(np->screen_name);
		free(np->text);
		free(np);
	}
}


static size_t
ti_get_since_id(char *since_id, ti_head *head, size_t len)
{
	struct ti_entry *np;

	np = TAILQ_LAST(head, ti_tailhead);
	return strlcpy(since_id, np->id, len);
}

static int
ti_process_xml(ti_head *head, char *xml_str)
{
	XML_Parser parser;
	ti_ctx ctx;

	if ((parser = XML_ParserCreate("UTF-8")) == NULL) {
		fprintf(stderr, "parser creation error\n");
		exit(1);
	}

	ctx.ent = NULL;
	ctx.head = head;
	ctx.depth = 0;
	XML_SetUserData(parser, &ctx);
	XML_SetElementHandler(parser, ti_element_start_cb, ti_element_end_cb);
	XML_SetCharacterDataHandler(parser, ti_characterdata_cb);
	XML_Parse(parser, xml_str, strlen(xml_str), 1);

	return 0;
}

/*
 * code from example/getinmemory.c in libcurl
 */
struct ti_mem {
	char *memory;
	size_t size;
};

static size_t
ti_fetch_cb(void *ptr, size_t size, size_t nmemb, void *data)
{
	size_t realsize = size * nmemb;
	struct ti_mem *mem = (struct ti_mem *)data;

	mem->memory = ti_xrealloc(mem->memory, mem->size + realsize + 1);
	if (mem->memory) {
		memcpy(&(mem->memory[mem->size]), ptr, realsize);
		mem->size += realsize;
		mem->memory[mem->size] = 0;
	}
	return realsize;
}

static int
ti_fetch_with_default(char **ret_str, CURL *curl_handle, const char *url)
{
	struct ti_mem chunk = { NULL, 0 };
	CURLcode curl_ret;
	int ret = 1;

	curl_easy_setopt(curl_handle, CURLOPT_URL, url);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, ti_fetch_cb);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);

	curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0);
	curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 1);

	curl_ret = curl_easy_perform(curl_handle);

	if (curl_ret != CURLE_OK) {
		printf("libcurl: %s\n", curl_easy_strerror(curl_ret));
		ret = 0;
	}

	*ret_str = chunk.memory;

	return ret;
}

static int
ti_fetch(char **ret_str, const char *url, const char *user, const char *passwd)
{
	CURL *curl_handle;
	int ret = 1;

	curl_global_init(CURL_GLOBAL_ALL);
	curl_handle = curl_easy_init();

	if (user) {
		char auth_str[1024];

		snprintf(auth_str, sizeof(auth_str), "%s:%s", user, passwd);
		curl_easy_setopt(curl_handle, CURLOPT_HTTPAUTH, (long)CURLAUTH_BASIC);
		curl_easy_setopt(curl_handle, CURLOPT_USERPWD, auth_str);
	}

	ret = ti_fetch_with_default(ret_str, curl_handle, url);

	curl_easy_cleanup(curl_handle);

	curl_global_cleanup();

	return ret;
}

static int
ti_send_update(const char *buf, const char *user, const char *passwd, const char *extra)
{
	CURL *curl_handle;
	char auth_str[1024];
	int ret = 1;
	char msg[1024];
	char *ret_str;

	if (!user)
		return 0;

	curl_global_init(CURL_GLOBAL_ALL);
	curl_handle = curl_easy_init();

	snprintf(msg, sizeof(msg), "status=%s&source=API%s", buf, extra);
	curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, msg);

	snprintf(auth_str, sizeof(auth_str), "%s:%s", user, passwd);
	curl_easy_setopt(curl_handle, CURLOPT_HTTPAUTH, (long)CURLAUTH_BASIC);
	curl_easy_setopt(curl_handle, CURLOPT_USERPWD, auth_str);

	ret = ti_fetch_with_default(&ret_str, curl_handle, TI_UPDATE_URL);

	curl_easy_cleanup(curl_handle);

	curl_global_cleanup();

	/* XXX */
	free(ret_str);

	return ret;
}

static int
ti_send_favorate(const char *user, const char *passwd, const char *id)
{
	CURL *curl_handle;
	char auth_str[1024];
	int ret = 1;
	char *ret_str;
	char url[1024], msg[1024];

	if (!user)
		return 0;

	curl_global_init(CURL_GLOBAL_ALL);
	curl_handle = curl_easy_init();

	snprintf(url, sizeof(url), TI_FAVORATE_URL "/%s.xml", id);

	snprintf(msg, sizeof(msg), "id=%s&source=API", id);
	curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, msg);

	snprintf(auth_str, sizeof(auth_str), "%s:%s", user, passwd);
	curl_easy_setopt(curl_handle, CURLOPT_HTTPAUTH, (long)CURLAUTH_BASIC);
	curl_easy_setopt(curl_handle, CURLOPT_USERPWD, auth_str);

	ret = ti_fetch_with_default(&ret_str, curl_handle, url);

	curl_easy_cleanup(curl_handle);

	curl_global_cleanup();

	/* XXX */
	free(ret_str);

	return ret;
}

static int
ti_make_io_dir(char *prefix)
{
	char path[MAXPATHLEN];

	mkdir(prefix, S_IRWXU);

	snprintf(path, sizeof(path), "%s/in", prefix);
	unlink(path);
	mkfifo(path, S_IRWXU);

	snprintf(path, sizeof(path), "%s/out", prefix);
	unlink(path);
	mkfifo(path, S_IRWXU);

	return 1;
}

static int
ti_open_io_files(ti_fds *fds, const char *prefix)
{
	char path[MAXPATHLEN];

	fds->prefix = strdup(prefix);

	snprintf(path, sizeof(path), "%s/in", prefix);
	if ((fds->input = open(path, O_RDONLY | O_NONBLOCK, S_IWUSR)) == -1) {
		perror("ti_open_io_files(\"in\")");
		exit(EXIT_FAILURE);
	}
	snprintf(path, sizeof(path), "%s/log", prefix);
	if ((fds->log = open(path, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR)) == -1) {
		perror("ti_open_io_files(\"log\")");
		exit(EXIT_FAILURE);
	}
	return 0;
}

#ifndef _WIN32
static int
ti_socket_ready(int fd)
{
	struct pollfd pfd;
	int ndfs;

	pfd.fd = fd;
	pfd.events = POLLIN;
	ndfs = poll(&pfd, 1, 0);

	if (ndfs < 0) {
		perror("poll");
		return 0;
	} else if (ndfs == 0)
		return 0;
	else
		return 1;
}
#else
static int
ti_socket_ready(int fd)
{
  fd_set fds;
  int nfds;
  struct timeval to;

  FD_ZERO(&fds);
  FD_SET(fd, &fds);
  to.tv_sec = 0;
  to.tv_usec = 0;
  nfds = select(1, &fds, NULL, NULL, &to);
  if (FD_ISSET(fd, &fds)) return 1;
  return 0;
}
#endif

static int
ti_read_line(int fd, char *buf, size_t len)
{
	unsigned char c;
	size_t i = 0;

	do {
		if (read(fd, &c, 1) == 0 || c == '\n') {
			buf[i] = '\0';
			break;
		}
		buf[i++] = c;
	} while (i < len);
	return i;
}

static int
ti_get_last_id(char *id, size_t id_len, const char *friend, const char *user, const char *passwd)
{
	char *buf;
	char url[1024];
	ti_head head;

	snprintf(url, sizeof(url), TI_USER_URL "/%s.xml?count=1", friend);
	if (!ti_fetch(&buf, url, user, passwd))
		printf("error");
	TAILQ_INIT(&head);
	ti_process_xml(&head, buf);
	free(buf);
	if (TAILQ_EMPTY(&head))
		return 0;
	else {
		struct ti_entry *np = TAILQ_FIRST(&head);
		strlcpy(id, np->id, id_len);
	}
	ti_free_entry(&head);
	return 1;
}

static int
ti_is_responce(char *friend, size_t friend_len, const char *buf)
{
	char *p;

	if (buf[0] != '@')
		return 0;
	strlcpy(friend, &buf[1], friend_len);
	if ((p = strchr(friend, ' ')) != NULL)
		*p = '\0';
	return 1;
}

static int
ti_is_favorate(char *friend, size_t friend_len, const char *buf)
{
	char *fav = "fav ";

	if (strlen(buf) < sizeof(fav) || strncmp(buf, fav, sizeof(fav)) != 0)
		return 0;
	strlcpy(friend, &buf[sizeof(fav)], friend_len);
	return 1;
}

static int
ti_process_cmd(ti_fds *fds, const char *user, const char *passwd)
{
	char line[1024];
	char id[1024];
	char friend[256];

	ti_read_line(fds->input, line, sizeof(line));
#ifdef _WIN32
	// on  win32, fifo is not supported. this is workaround as ...orz
	{
		char path[MAXPATHLEN];
		close(fds->input);
		snprintf(path, sizeof(path), "%s/in", fds->prefix);
		unlink(path);
		if ((fds->input = open(path, O_RDONLY | O_NONBLOCK | O_CREAT, S_IWUSR)) == -1) {
			perror("ti_process_cmd(\"in\")");
			exit(EXIT_FAILURE);
		}
	}
#endif

	if (ti_is_responce(friend, sizeof(friend), line)) {
		char resp[256];

		if (ti_get_last_id(id, sizeof(id), friend, user, passwd)) {
			snprintf(resp, sizeof(resp), "&in_reply_to_status_id=%s", id);
			ti_send_update(line, user, passwd, resp);
		} else
			ti_send_update(line, user, passwd, "");
	} else if (ti_is_favorate(friend, sizeof(friend), line)) {
		if (ti_get_last_id(id, sizeof(id), friend, user, passwd))
			ti_send_favorate(user, passwd, id);
	} else
		ti_send_update(line, user, passwd, "");

	return 1;
}

static void
usage(void)
{
	printf("ti [-k passwd] [-t prefix] [-u user] [-w interval]\n");
	exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
	char *buf;
	ti_head head;
	ti_fds fds;
	int ch;
	char *user = NULL, *passwd = NULL;
	char *prefix = NULL;
	int interval = 60;
	char since_id[1024];
	const char *errstr;

	while ((ch = getopt(argc, argv, "k:t:u:w:")) != -1) {
		switch (ch) {
		case 'k':
			free(passwd);
			passwd = strdup(optarg);
			break;
		case 't':
			free(prefix);
			prefix = strdup(prefix);
			break;
		case 'u':
			free(user);
			user = strdup(optarg);
			break;
		case 'w':
			interval = (int)strtonum(optarg, 1, 100000, &errstr);
                        if (errstr) {
				printf("number of iterations is %s: %s\n", errstr, optarg);
                                usage();
                        }
                        break;
		default:
			usage();
		}
	}

	if (user && !passwd)
		passwd = getpass("Password: ");

	if (!prefix) {
#ifndef _WIN32
		struct passwd *pw;

		pw = getpwuid(getuid());
		asprintf(&prefix, "%s/ti", pw->pw_dir);
		endpwent();
#else
		char* env = getenv("HOME");
		if (!env) env = getenv("USERPROFILE");
		if (env) {
			prefix = malloc(strlen(env) + 4);
			strcpy(prefix, env);
			strcat(prefix, "/ti");
		}
#endif
	}

	ti_make_io_dir(prefix);
	ti_open_io_files(&fds, prefix);

	TAILQ_INIT(&head);
	since_id[0] = '\0';

	while (1) {
		char url[1024];

		if (!user) {
			if (since_id[0] == '\0')
				strlcpy(url, TI_PUBLIC_URL, sizeof(url));
			else
				snprintf(url, sizeof(url), TI_PUBLIC_URL "?since_id=%s", since_id);
		} else {
			if (since_id[0] == '\0')
				snprintf(url, sizeof(url), TI_FRIEND_URL "/%s.xml", user);
			else
				snprintf(url, sizeof(url), TI_FRIEND_URL "/%s.xml?since_id=%s", user, since_id);
		}
		if (!ti_fetch(&buf, url, user, passwd))
			goto next_fetch;
		ti_process_xml(&head, buf);
		if (!TAILQ_EMPTY(&head)) {
			ti_write_entry(&head, &fds);
			ti_get_since_id(since_id, &head, sizeof(since_id));
			ti_free_entry(&head);
		}
		if (ti_socket_ready(fds.input))
			ti_process_cmd(&fds, user, passwd);
		free(buf);
	next_fetch:
		sleep(interval);
	}

	return 1;
}
