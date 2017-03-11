/*
 * hlog.h
 *
 *  Created on: Mar 10, 2017
 *      Author: huyong 670460204@qq.com
 */

#ifndef HLOG_H_
#define HLOG_H_

#include <stddef.h>

#define FILENAME_LEN 1024
#define LOG_STR_LEN  2048

typedef void * hlog_t;

enum hlog_level {
	HLOG_TRACE = 0,
	HLOG_DEBUG,
	HLOG_INFO,
	HLOG_WARN,
	HLOG_ERROR,
	HLOG_FATAL,
	HLOG_LEVEL_NUM
};

/**
 * @param dir          log directory
 *        name         process name
 *        level        log level
 *        max_filesize log filesize ( > pagesize)
 *        max_nfiles   number of files( > 1)
 *        interval     flush interval( > 0 )
 *        terminal     if output to ternimal ( 0 or 1)
 *        ofd          fd of send to other node  (< 2 close)
 */
hlog_t hlog_init(const char *dir, const char *name,
		enum hlog_level level, size_t max_filesize, int max_nfiles,
		int interval, int terminal, int ofd);
void hlog_fini(hlog_t hlog);
int hlog(hlog_t hlog, enum hlog_level level,
		const char *file, int line, const char *fmt, ...);


#endif /* HLOG_H_ */
