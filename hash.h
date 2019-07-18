#ifndef _TOOL_H_
#define _TOOL_H_
#include <stdio.h>
#include <sys/types.h>
#include <sys/shm.h>

int gethash(char *string,char *hash);
int gethash_i(char *string,unsigned long long *a, unsigned long long *b);

#endif
