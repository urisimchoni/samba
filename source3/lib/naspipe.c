/* naspipe.c - a pipe to CTERA nas */
#include "includes.h"

void naspipe_output(const char *fmt, ...);

void naspipe_output(const char *fmt, ...)
{
	FILE *fp = fopen("/dev/naspipe", "w");
	if (fp) {
		va_list ap;
		va_start(ap, fmt);
		vfprintf(fp, fmt, ap);
		va_end(ap);
		fclose(fp);
	}
}
