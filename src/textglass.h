#ifndef _TEXTGLASS_H_INCLUDED_
#define _TEXTGLASS_H_INCLUDED_


#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#define TEXTGLASS_VERSION		"1.0.0"


#define TG_DEBUG_LOGGING		1
#define TG_DEBUG_LEVEL			3


void tg_printd(int level, const char* fmt,...);

#endif	/* _TEXTGLASS_H_INCLUDED_ */