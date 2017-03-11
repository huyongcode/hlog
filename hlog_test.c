/*
 * hlog_test.c
 *
 *  Created on: Mar 11, 2017
 *      Author: huyong 670460204@qq.com
 */

#include "hlog.h"
#include <unistd.h>

void test0(void);
void test1(void);
void test2(void);

int main(int argc, char *argv[])
{
//	test0();
	test1();
//	test2();
	return 0;
}

void test0(void)
{
	hlog_t log = hlog_init(".", "hlog", HLOG_DEBUG, 4096, 10, 500, 1, 0);
	if (log == NULL)
		return;
	hlog(log, HLOG_TRACE, __FILE__, __LINE__, "you are %d%d", 0, 0);
	hlog(log, HLOG_DEBUG, __FILE__, __LINE__, "you are %d%d", 1, 1);
	hlog(log, HLOG_INFO, __FILE__, __LINE__, "you are %d%d",2, 2);
	hlog(log, HLOG_WARN, __FILE__, __LINE__, "you are %d%d", 3, 3);
	hlog(log, HLOG_ERROR, __FILE__, __LINE__, "you are %d%d", 4, 4);

	hlog_fini(log);
}

void test1(void)
{
	int i;
	int n = 1000;
	hlog_t log = hlog_init(".", "hlog", HLOG_DEBUG, 4096, 10, 500, 0, 0);
	if (log == NULL)
		return;
	for (i = 0; i < n; i++) {
		hlog(log, HLOG_TRACE, __FILE__, __LINE__, "you are %d", i);
		hlog(log, HLOG_DEBUG, __FILE__, __LINE__, "you are %d", i);
		hlog(log, HLOG_INFO, __FILE__, __LINE__, "you are %d", i);
		hlog(log, HLOG_WARN, __FILE__, __LINE__, "you are %d", i);
		hlog(log, HLOG_ERROR, __FILE__, __LINE__, "you are %d", i);
	}
//	sleep(3);
	hlog_fini(log);
}

void test2(void)
{

}


