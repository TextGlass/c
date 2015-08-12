#ifndef _TEXTGLASS_H_INCLUDED_
#define _TEXTGLASS_H_INCLUDED_


#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <time.h>

#include "jsmn.h"


#define TEXTGLASS_VERSION		"1.0.0"

#define TG_DEBUG_LOGGING		1


typedef struct
{
	unsigned int		magic;
#define TG_JSONFILE_MAGIC	0xCD1C4F8B

	char			*json;
	size_t			json_len;

	jsmntok_t		*tokens;
	int			token_len;

	const char		*type;
	const char		*domain;
	const char		*domain_version;
}
tg_jsonfile;

typedef struct
{
	unsigned int		magic;
#define TG_DOMAIN_MAGIC		0x4C3A041E

	tg_jsonfile		*pattern;
	tg_jsonfile		*attribute;
	tg_jsonfile		*pattern_patch;
	tg_jsonfile		*attribute_patch;

	const char		*domain;
	const char		*domain_version;
}
tg_domain;


extern int tg_printd_debug_level;

void tg_printd(int level, const char* fmt,...);
void tg_time_diff(struct timespec *end, struct timespec *start, struct timespec *result);


tg_jsonfile *tg_jsonfile_get(const char *file);
void tg_jsonfile_free(tg_jsonfile *jsonfile);
void tg_jsonfile_free_tokens(tg_jsonfile *jsonfile);
jsmntok_t *tg_json_get(tg_jsonfile *jsonfile, jsmntok_t *tokens, const char *field);

#define TG_JSON_STR(jsonfile, token) ((token) ? (jsonfile)->json + (token)->start : "")
#define TG_JSON_STR_NULL(jsonfile, token) ((token) ? (jsonfile)->json + (token)->start : NULL)
#define TG_JSON_GET_STR(jsonfile, tokens, attr) \
		TG_JSON_STR_NULL((jsonfile), tg_json_get((jsonfile), (tokens), attr))


tg_domain *tg_domain_load(const char *pattern, const char *attribute,
		const char *pattern_patch, const char *attribute_patch);
void tg_domain_free(tg_domain *domain);

#endif	/* _TEXTGLASS_H_INCLUDED_ */