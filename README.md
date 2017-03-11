# hlog

## multipl function, high performance log engine
 - use sendfile for sending logs to remote node
 - use mmap for storing log in kernel page cache, avoid lost logs when proccess crushed or OS rebooted
 - set number of logs in local disk
 - set max filesize of a log


## example
 
```
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
```
