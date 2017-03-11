/*
 * hlog.c
 *
 *  Created on: Mar 10, 2017
 *      Author: huyong 670460204@qq.com
 */

#include "hlog.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <assert.h>
#include <sys/sendfile.h>

#define SIZE_ALIGN(s, a) (((s) + (a) - 1) & (~((a) - 1)))
#define TIME_STR_LEN 24
#define HLOG_MALLOC  malloc
#define HLOG_FREE    free

struct file_info {
	char filename[FILENAME_LEN];
	int fd;
	int index;
	void *addr;
	void *ptr;
	void *sync_ptr;
	size_t size;
	struct file_info *next;
};

struct file_info_list {
	struct file_info *head;
	struct file_info *tail;
};

struct hlog {
	const char *dir;
	const char *name;
	int pagesize;
	int index;
	int start_reserve_index;
	int cur_nfiles;
	enum hlog_level level;
	uint64_t module_mask;
	size_t max_filesize;
	int max_nfiles;
	int interval;
	int terminal;
	int ofd;
	struct file_info *cur_fi;
	pthread_mutex_t mutex;
	pthread_t flush_tid;
	volatile int flush_exit;

	pthread_t list_tid;
	volatile int list_exit;
	pthread_mutex_t list_mutex;
	pthread_cond_t list_cond;
	struct file_info_list fi_list;
	int list_count;
};

static const char *level_name[] = {
		"TRACE", "DEBUG", "INFO ", "WARN ", "ERROR", "FATAL"
};

static void fi_list_init(struct file_info_list *fi_list)
{
	fi_list->head = NULL;
	fi_list->tail = NULL;
}

static void fi_list_push(struct file_info_list *fi_list, struct file_info *fi)
{
	if (fi_list->tail != NULL) {
		fi_list->tail->next = fi;
	} else {
		fi_list->head = fi;
	}

	fi_list->tail = fi;
	fi->next = NULL;
}

static struct file_info *fi_list_pull(struct file_info_list *fi_list)
{
	struct file_info *head;

	head = fi_list->head;
	if (head == NULL) {
		return NULL;
	}
	fi_list->head = fi_list->head->next;
	if (fi_list->head == NULL) {
		fi_list->tail = NULL;
	}
	head->next = NULL;
	return head;
}

static void fi_delete(struct file_info *fi)
{
	assert(fi != NULL);
	if (close(fi->fd) != 0) {
		perror("ERROR: close");
	}
	fi->fd = -1;
	HLOG_FREE(fi);
}

static struct file_info *fi_open(const char *filename, size_t size, int index)
{
	struct file_info *fi;

	fi = (struct file_info *)HLOG_MALLOC(sizeof(*fi));
	if (fi == NULL) {
		fprintf(stderr, "ERROR: no memory\n");
		return NULL;
	}

	fi->fd = open(filename, O_CREAT | O_RDWR | O_APPEND, 0644);
	if (fi->fd == -1) {
		perror("ERROR: open");
		HLOG_FREE(fi);
		return NULL;
	}

	if (ftruncate(fi->fd, size) != 0) {
		perror("ERROR: ftruncate");
		fi_delete(fi);
		return NULL;
	}

	fi->addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fi->fd, 0);
	if (fi->addr == MAP_FAILED) {
		perror("ERROR: mmap");
		fi_delete(fi);
		return NULL;
	}

	strncpy(fi->filename, filename, sizeof(fi->filename));
	fi->ptr = fi->addr;
	fi->sync_ptr = fi->ptr;
	fi->size = size;
	fi->index = index;
	return fi;
}

static int fi_is_available(const struct file_info *fi, size_t len)
{
	size_t available;
	if (fi == NULL) {
		return 0;
	}
	/* must use sub to avoid int overflow! */
	available = fi->size - ((uintptr_t)fi->ptr - (uintptr_t)fi->addr);
	return (int)(available >= len);
}

static void fi_append(struct file_info *fi, const void *buff, size_t len)
{
	assert(fi != NULL && buff != NULL);
	memcpy(fi->ptr, buff, len);
	fi->ptr = (void *)((uintptr_t)fi->ptr + len);
	return ;
}

static void fi_close(struct file_info *fi)
{
	assert(fi != NULL);
	size_t len = (uintptr_t)fi->ptr - (uintptr_t)fi->addr;

	if (munmap(fi->addr, fi->size) == -1) {
		perror("ERROR: munmap");
	}

	if (ftruncate(fi->fd, len) != 0) {
		perror("Error: ftruncate");
	}

	fi_delete(fi);
}

static inline int getlogname(struct hlog *log, int index,
		char filename[], size_t size)
{
	return snprintf(filename, size, "%s/%s_%u_%d.log",
			log->dir, log->name, (unsigned int)getpid(), index);
}

static int fi_list_empty(const struct file_info_list *fi_list)
{
	return (int)(fi_list->head == NULL);
}

static unsigned int gettid(void)
{
	return (unsigned int)pthread_self();
}

static const char *basename(const char *filepath)
{
	char *base = strrchr(filepath, '/');
#ifdef OS_WINDOW
	if (base == NULL) {
		base = strrchr(filepath, '\\');
	}
#endif
	return base ? (base + 1) : filepath;
}

static size_t gettimestr(char str[], size_t size)
{
	time_t t;
	struct tm local;

	time(&t);
	localtime_r(&t, &local);
	return strftime(str, size, "%Y-%m-%d %H:%M:%S", &local);
}

static int raw_log(char** buf, int* size, const char* format, ...)
{
	va_list ap;
	int n;

	va_start(ap, format);
	n = vsnprintf(*buf, *size, format, ap);
	va_end(ap);
	if (n < 0 || n > *size) {
		return -1;
	}
	*size -= n;
	*buf += n;
	return 0;
}

static inline int va_log(char** buf, int* size,
		const char* format, va_list ap)
{
	int n = vsnprintf(*buf, *size, format, ap);
	if (n < 0 || n > *size) {
		return -1;
	}
	*size -= n;
	*buf += n;
	return 0;
}

int send_file(int ofd, int ifd, size_t len)
{
	ssize_t r;
	off_t offset = 0;
	size_t count = len;

	if (ofd <= 2) { // must be remote
		return 0;
	}

	while(count > 0) {
		r = sendfile(ofd, ifd, &offset, count);
		if (r < 0) {
			if (errno == EAGAIN) {
				continue;
			}
			perror("ERROR: sendfile");
			return -1;
		} else if (r == 0) {
			fprintf(stderr, "ERROR: peer closed\n");
			return -1;
		} else {
			count -= r;
		}
	}

	return 0;
}

static void *flush_log(void *arg)
{
	struct hlog *log = (struct hlog *)arg;
	void *sptr = NULL;
	size_t len;

	for (;;) {
		usleep(log->interval);

		pthread_mutex_lock(&log->mutex);
		if (log->flush_exit) {
			pthread_mutex_unlock(&log->mutex);
			return NULL;
		}
		if (log->cur_fi != NULL) {
			sptr = (void *)SIZE_ALIGN((uintptr_t)(log->cur_fi->sync_ptr),
					log->pagesize);

			/* lock this ptr */
			len = (uintptr_t)log->cur_fi->ptr - (uintptr_t)sptr;

			/* add previous */
			log->cur_fi->sync_ptr += len;
		}
		pthread_mutex_unlock(&log->mutex);

		if (sptr == NULL) {
			continue;
		}
		if (msync(sptr, len, MS_SYNC) != 0) {
			perror("ERROR: msync");
		}
	}

	return arg;
}

static void *flush_list(void *arg)
{
	struct hlog *log = (struct hlog *)arg;
	struct file_info *fi;
	int list_count;
	char filename[FILENAME_LEN];
	int nrm;
	int i;

	for (;;) {
		pthread_mutex_lock(&log->list_mutex);
		if (log->list_exit) {
			pthread_mutex_unlock(&log->list_mutex);
			return NULL;
		}
		while (!log->list_exit && fi_list_empty(&log->fi_list)) {
			pthread_cond_wait(&log->list_cond, &log->list_mutex);
		}
		pthread_mutex_unlock(&log->list_mutex);

		for(;;) {
			pthread_mutex_lock(&log->list_mutex);
			fi = fi_list_pull(&log->fi_list);
			if (fi == NULL) {
				pthread_mutex_unlock(&log->list_mutex);
				break;
			}
			list_count = log->list_count--;
			pthread_mutex_unlock(&log->list_mutex);

			/* TODO: compress log */

			(void)send_file(log->ofd, fi->fd, fi->size);

			pthread_mutex_lock(&log->mutex);
			nrm = log->cur_nfiles - log->max_nfiles;
			pthread_mutex_unlock(&log->mutex);
			/* remove redundant disk logs */
			for (i = 0;
					nrm > 0 && log->start_reserve_index + i != fi->index;
					i++) {
				(void)getlogname(log, log->start_reserve_index + i,
						filename, sizeof(filename));
				if (unlink(filename) != 0) {
					perror("ERROR: unlink");
					fprintf(stderr, "ERROR nrm: unlink %s failed\n", filename);
				}

			}
			log->start_reserve_index += i;
			pthread_mutex_lock(&log->mutex);
			log->cur_nfiles -= i;
			pthread_mutex_unlock(&log->mutex);

			/* remove redundant memory logs */
			if (list_count > log->max_nfiles) { /* no lock max_nfiles */
				if (unlink(fi->filename) != 0) {
					perror("ERROR: unlink");
					fprintf(stderr, "ERROR: unlink %s failed\n", fi->filename);
				}
				fi_delete(fi);
				log->start_reserve_index++;
				pthread_mutex_lock(&log->mutex);
				log->cur_nfiles--;
				pthread_mutex_unlock(&log->mutex);
			} else {
				fi_close(fi);
			}
		}
	}

	return arg;
}

hlog_t hlog_init(const char *dir, const char *name,
		enum hlog_level level, size_t max_filesize, int max_nfiles,
		int interval, int terminal, int ofd)
{
	int ret;
	struct hlog *log;
	int pagesize;

	pagesize = getpagesize();

	if (max_filesize < pagesize || max_nfiles < 1) {
		return NULL;
	}

	log = (struct hlog *)HLOG_MALLOC(sizeof(*log));
	if (log == NULL) {
		fprintf(stderr, "ERROR: no memory\n");
		return NULL;
	}

	memset(log, 0, sizeof(struct hlog));
	log->dir = dir;
	log->name = name;
	log->pagesize = pagesize;
	log->index = 0;
	log->cur_nfiles = 0;
	log->start_reserve_index = 0;
	log->level = level;
	log->max_filesize = SIZE_ALIGN(max_filesize, log->pagesize);
	log->max_nfiles = max_nfiles;
	log->interval = interval;
	log->terminal = terminal;
	log->ofd = ofd;
	log->cur_fi = NULL;

	log->module_mask = 0;
	log->flush_exit = 0;
	log->list_exit = 0;

	fi_list_init(&log->fi_list);
	log->list_count = 0;

	ret = pthread_mutex_init(&log->mutex, NULL);
	if (ret != 0) {
		goto err;
	}
	ret = pthread_mutex_init(&log->list_mutex, NULL);
	if (ret != 0) {
		goto err;
	}
	ret = pthread_cond_init(&log->list_cond, NULL);
	if (ret != 0) {
		goto err;
	}
	ret = pthread_create(&log->flush_tid, NULL, flush_log, (void *)log);
	if (ret != 0) {
		goto err;
	}
	ret = pthread_create(&log->list_tid, NULL, flush_list, (void *)log);
	if (ret != 0) {
		goto err;
	}

	return (hlog_t)log;
err:
	free(log);
	return NULL;
}

void hlog_fini(hlog_t hlog)
{
	struct hlog *log = (struct hlog *)hlog;
	struct file_info *fi;
	pthread_mutex_lock(&log->mutex);
	log->flush_exit = 1;
	pthread_mutex_unlock(&log->mutex);

	pthread_mutex_lock(&log->list_mutex);
	log->list_exit = 1;
	pthread_cond_signal(&log->list_cond);
	while ((fi = fi_list_pull(&log->fi_list)) != NULL) {
		fi_delete(fi);
	}
	pthread_mutex_unlock(&log->list_mutex);


	HLOG_FREE(hlog);
}

int hlog(hlog_t hlog, enum hlog_level level,
		const char *file, int line, const char *fmt, ...)
{
	char buffer[LOG_STR_LEN];
	char filename[FILENAME_LEN];
	char timestr[TIME_STR_LEN];
	int size = sizeof(buffer);
	int left = size;
	char *buf = buffer;

	struct hlog *log = (struct hlog *)hlog;
	va_list ap;
	size_t no_chop;
	struct file_info *fi;
	struct file_info *old_fi;


//	const char* msg_start;
//	const size_t msg_size;

	if (level < log->level) {
		return 0;
	}

	/* get log string */
	(void)gettimestr(timestr, sizeof(timestr));
	(void)raw_log(&buf, &left, "[%s %x %s %s:%d]: ",
			level_name[level], gettid(), timestr, basename(file), line);

//	msg_start = buf;
//	msg_size = left;
	va_start(ap, fmt);
	no_chop = va_log(&buf, &left, fmt, ap);
	va_end(ap);
	if (no_chop == 0) {
		(void)raw_log(&buf, &left, "\n");
	} else {
		(void)raw_log(&buf, &left, "ERROR: The Message was too long!\n");
	}

	if (log->terminal) {
		fprintf(stderr, "%s", buffer);
	}

	/* check if new log file */
	pthread_mutex_lock(&log->mutex);
	if (!fi_is_available(log->cur_fi, size - left)) {
		log->cur_nfiles++;
		if (log->cur_nfiles < 0) {
			fprintf(stderr, "ERROR: cur_nfiles overflow\n");
			pthread_mutex_unlock(&log->mutex);
			return -1;
		}
		(void)getlogname(log, log->index, filename, sizeof(filename));
		fi = fi_open(filename, log->max_filesize, log->index);
		if (fi == NULL) {
			pthread_mutex_unlock(&log->mutex);
			return -1;
		}

		old_fi = log->cur_fi;
		log->cur_fi = fi;
		log->index++;


		fi_append(log->cur_fi, buffer, size - left);

		pthread_mutex_unlock(&log->mutex);

		if (old_fi != NULL) {
			pthread_mutex_lock(&log->list_mutex);
			fi_list_push(&log->fi_list, old_fi);
			log->list_count++;
			pthread_cond_signal(&log->list_cond);
			pthread_mutex_unlock(&log->list_mutex);
		}

	} else {
		fi_append(log->cur_fi, buffer, size - left);
		pthread_mutex_unlock(&log->mutex);
	}
	/* flush list */

	if (level == HLOG_FATAL) {
		fprintf(stderr, "exit\n");
		abort();
	}

	return 0;
}




