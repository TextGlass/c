#ifndef _TEXTGLASS_H_INCLUDED_
#define _TEXTGLASS_H_INCLUDED_


#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>

#include "list.h"
#include "hashtable.h"
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

typedef enum
{
	TG_RANKTYPE_NONE =0,
	TG_RANKTYPE_WEAK = 1,
	TG_RANKTYPE_STRONG = 2
}
tg_rank_type;

typedef enum
{
	TG_PATTERN_SIMPLE = 0,
	TG_PATTERN_AND = 1,
	TG_PATTERN_ORDERED_AND = 2
}
tg_pattern_type;

typedef struct
{
	unsigned int		magic;
#define TG_PATTERN_MAGIC	0x8BE15F7A

	const char		*pattern_id;

	tg_rank_type		rank_type;
	int			rank_value;

	tg_pattern_type		pattern_type;

	tg_list			pattern_tokens;

	int			malloc:1;
	int			pattern_token_init:1;

	unsigned long		ref_count;
}
tg_pattern;

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

	tg_list			*input_transformers;

	const char		**token_seperators;
	int			token_seperator_len;

	const char		*default_id;

	tg_list			*list_slab;
	size_t			list_slab_size;
	size_t			list_slab_pos;

	tg_pattern		*pattern_slab;
	size_t			pattern_slab_size;
	size_t			pattern_slab_pos;

	tg_hashtable		*patterns;
}
tg_domain;

typedef struct
{
	unsigned int		magic;
#define TG_CLASSIFIED_MAGIC	0x5B8A23EF

	tg_domain		*domain;

	tg_list			*matched_tokens;
	tg_list			*candidates;

	tg_list			*free_list;
}
tg_classified;

typedef struct tg_transformer
{
	unsigned int		magic;
#define TG_TRANSFORMER_MAGIC	0x940CE11D

	char*(*transformer)	(tg_list*,struct tg_transformer*,char*);

	const char		*s1;
	const char		*s2;

	int			i1;
	int			i2;
}
tg_transformer;


#define TG_FREE				void(*)(void*)


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

#define TG_JSON_IS_OBJECT(token)	((token) && (token)->type == JSMN_OBJECT)
#define TG_JSON_IS_STRING(token)	((token) && (token)->type == JSMN_STRING)
#define TG_JSON_IS_ARRAY(token)		((token) && (token)->type == JSMN_ARRAY)
#define TG_JSON_IS_LITERAL(token)	((token) && (token)->type == JSMN_PRIMITIVE)


tg_domain *tg_domain_load(const char *pattern, const char *attribute,
		const char *pattern_patch, const char *attribute_patch);
void tg_domain_free(tg_domain *domain);


void tg_classify(tg_domain *domain, const char *original);


tg_pattern *tg_pattern_alloc();
tg_pattern *tg_pattern_get(tg_domain *domain);
tg_pattern *tg_pattern_create(tg_pattern *pattern, jsmntok_t *tokens);
void tg_pattern_free(tg_pattern *pattern);


tg_list *tg_transformer_compile(jsmntok_t *tokens);
void tg_transformer_free(tg_transformer *transformer);


#endif	/* _TEXTGLASS_H_INCLUDED_ */