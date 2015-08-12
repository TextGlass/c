#ifndef _TEXTGLASS_H_INCLUDED_
#define _TEXTGLASS_H_INCLUDED_


#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include "jsmn.h"

#define TEXTGLASS_VERSION		"1.0.0"


#define TG_DEBUG_LOGGING		1
#define TG_DEBUG_LEVEL			3


#define TG_JSON_STR(jsonfile, token) ((token) ? (jsonfile)->json + (token)->start : "null")


typedef struct
{
	char			*json;
	size_t			json_len;

	jsmntok_t		*tokens;
	int			token_len;
}
tg_jsonfile;


void tg_printd(int level, const char* fmt,...);

tg_jsonfile *tg_jsonfile_get(char *file);
void tg_jsonfile_free(tg_jsonfile *jsonfile);
jsmntok_t *tg_json_get(tg_jsonfile *jsonfile, jsmntok_t *tokens, const char *field);

#endif	/* _TEXTGLASS_H_INCLUDED_ */