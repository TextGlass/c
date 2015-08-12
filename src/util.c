#include "textglass.h"

int tg_printd_debug_level = 1;

void tg_printd(int level, const char* fmt,...)
{
#if TG_DEBUG_LOGGING
	va_list ap;

	if(level <= tg_printd_debug_level)
	{
		if(level == 1)
		{
			printf("  ");
		}
		else if(level == 2)
		{
			printf("    ");
		} else if(level == 3)
		{
			printf("      ");
		}

		va_start(ap, fmt);
		vprintf(fmt, ap);
		va_end(ap);
	}
#endif
}

void tg_time_diff(struct timespec *end, struct timespec *start, struct timespec *result)
{
    result->tv_sec = end->tv_sec - start->tv_sec;
    result->tv_nsec = end->tv_nsec - start->tv_nsec;

    if(result->tv_nsec < 0)
    {
      result->tv_sec--;
      result->tv_nsec += (1000 * 1000 * 1000);
    }
}
