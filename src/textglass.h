#ifndef _TEXTGLASS_H_INCLUDED_
#define _TEXTGLASS_H_INCLUDED_


#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <time.h>

#include "list.h"
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

	const char		**token_seperators;
	int			token_seperator_len;

	const char		*default_id;
}
tg_domain;


extern int tg_printd_debug_level;

void tg_printd(int level, const char* fmt,...);
void tg_time_diff(struct timespec *end, struct timespec *start, struct timespec *result);
void tg_split(char *source, size_t source_len, const char **seps, int sep_length, tg_list *tokens);


tg_jsonfile *tg_jsonfile_get(const char *file);
void tg_jsonfile_free(tg_jsonfile *jsonfile);
void tg_jsonfile_free_tokens(tg_jsonfile *jsonfile);
jsmntok_t *tg_json_get(jsmntok_t *tokens, const char *field);
const char *tg_json_get_str(jsmntok_t *tokens, const char *field);
jsmntok_t *tg_json_array_get(jsmntok_t *tokens, int index);

#define TG_JSON_IS_OBJECT(token)		((token) && (token)->type == JSMN_OBJECT)
#define TG_JSON_IS_STRING(token)		((token) && (token)->type == JSMN_STRING)
#define TG_JSON_IS_ARRAY(token)			((token) && (token)->type == JSMN_ARRAY)
#define TG_JSON_IS_LITERAL(token)		((token) && (token)->type == JSMN_PRIMITIVE)


tg_domain *tg_domain_load(const char *pattern, const char *attribute,
		const char *pattern_patch, const char *attribute_patch);
void tg_domain_free(tg_domain *domain);
void tg_classify(tg_domain *domain, const char *original);


#endif	/* _TEXTGLASS_H_INCLUDED_ */