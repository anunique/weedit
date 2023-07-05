#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/types.h>

void myerror(__int32_t errcode, const char *bla, ...)
{
	char buffer[1024];
	va_list args;
	va_start(args, bla);
	vsnprintf(buffer, 1024, bla, args);
	printf("%s\n", buffer);
	va_end(args);
	if (errcode < 0)
		exit(-1);
}