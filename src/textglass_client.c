#include "textglass.h"

void tg_printd(int level, const char* fmt,...)
{
#if TG_DEBUG_LOGGING
	va_list ap;

	if(level <= TG_DEBUG_LEVEL)
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
