#include "syscalldb.h"
#include <stdarg.h>
#include <errno.h>

int register_library (const char * name, void * load_address)
	__attribute__((weak));

int register_library (const char * name, void * load_address)
{
	return 0;
}

long int glibc_option (const char * opt)
{
	return -EINVAL;
}
