#include "textglass.h"

void tg_printd(int level, const char* fmt,...)
{
#if TG_DEBUG_LOGGING
    va_list ap;

    if(level <= TG_DEBUG_LEVEL)
    {
        va_start(ap,fmt);

        vprintf(fmt,ap);

        va_end(ap);
    }
#endif
}
