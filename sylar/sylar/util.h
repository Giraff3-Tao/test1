#ifndef __SYLAR_UTIL_H__
#define __SYLAR_UTIL_H__

#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <stdio.h>

namespace sylar{
	//获取线程id
	pid_t GetThreadId();
	//获取协程id
	uint32_t GetFiberId();

}

#endif