/*
 * Copyright (c) 2015 TextGlass
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */

#ifndef _TEXTGLASS_H_INCLUDED_
#define _TEXTGLASS_H_INCLUDED_


#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>

#ifndef _TEXTGLASS_SKIP_ASSERT
#include <assert.h>
#endif

#include "list.h"
#include "hashtable.h"
#include "jsmn.h"


#define TEXTGLASS_VERSION	"1.0.0-beta"

#define TG_DEBUG_LOGGING	1


typedef struct
{
	unsigned int		magic;
#define TG_JSONFILE_MAGIC	0xCD1C4F8B

	char			*json;
	size_t			json_len;

	jsmntok_t		*tokens;
	long			token_len;

	const char		*type;
	const char		*domain;
	const char		*domain_version;
}
tg_jsonfile;


typedef struct
{
	unsigned int		magic;
#define TG_MEMALLOC_MAGIC	0xF128ED6B

	void			*buf;

	size_t			available;
	size_t			used;

	tg_list			*free_list;

	int			enabled:1;
}
tg_memalloc;


typedef enum
{
	TG_RANKTYPE_NONE = 0,
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


typedef enum
{
	TG_ERROR_NONE = 0,
	TG_ERROR_TRANSFORM = 1,
	TG_ERROR_MEMORY = 2
}
tg_error_code;


typedef struct
{
	unsigned int		magic;
#define TG_ATTRIBUTES_MAGIC	0xF45A0AC2

	tg_error_code		error_code;

	tg_memalloc		memalloc;

	const char		*pattern_id;

	int			user_malloc:1;

	const char		**keys;
	const char		**values;

	size_t			key_len;

	tg_list			*transformers;

	const char		*buf[0];
}
tg_attributes;

typedef const tg_attributes	tg_result;
#define TG_RESULT_MAGIC		TG_ATTRIBUTES_MAGIC


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
	int			pattern_tokens_init:1;

	unsigned long		ref_count;

	tg_attributes		*attributes;
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
	long			token_seperator_len;

	unsigned long		ngram_size;

	const char		*default_id;
	tg_attributes		*default_attributes;

	tg_attributes		error_attributes[2];

	tg_list			*list_slab;
	size_t			list_slab_size;
	size_t			list_slab_pos;

	tg_pattern		*pattern_slab;
	size_t			pattern_slab_size;
	size_t			pattern_slab_pos;

	tg_hashtable		*patterns;

	tg_hashtable		*attribute_index;
}
tg_domain;


typedef struct
{
	unsigned int		magic;
#define TG_CLASSIFIED_MAGIC	0x5B8A23EF

	const tg_domain		*domain;

	tg_list			*tokens;
	tg_list			*matched_tokens;
	tg_list			*candidates;

	tg_memalloc		memalloc;
}
tg_classified;


typedef struct tg_transformer
{
	unsigned int		magic;
#define TG_TRANSFORMER_MAGIC	0x940CE11D

	char*			(*transformer)(tg_memalloc*,struct tg_transformer*,char*);

	const char		*s1;
	const char		*s2;

	long			i1;
	long			i2;
}
tg_transformer;


#define TG_FREE			void(*)(void*)


extern int tg_printd_debug_level;

void tg_printd(int level, const char* fmt, ...);
void tg_time_diff(struct timespec *end, struct timespec *start, struct timespec *result);
void tg_split(char *source, size_t source_len, const char **seps, long sep_length, tg_list *tokens);


tg_jsonfile *tg_jsonfile_get(const char *file);
void tg_jsonfile_free(tg_jsonfile *jsonfile);
void tg_jsonfile_free_tokens(tg_jsonfile *jsonfile);
jsmntok_t *tg_json_get(jsmntok_t *tokens, const char *field);
const char *tg_json_get_str(jsmntok_t *tokens, const char *field);

#define TG_JSON_IS_OBJECT(token)	((token) && (token)->type == JSMN_OBJECT)
#define TG_JSON_IS_STRING(token)	((token) && (token)->type == JSMN_STRING)
#define TG_JSON_IS_ARRAY(token)		((token) && (token)->type == JSMN_ARRAY)
#define TG_JSON_IS_LITERAL(token)	((token) && (token)->type == JSMN_PRIMITIVE)


tg_domain *tg_domain_load(const char *pattern, const char *attribute,
		const char *pattern_patch, const char *attribute_patch);
void tg_domain_free(tg_domain *domain);


tg_result *tg_classify(const tg_domain *domain, const char *original);
tg_result *tg_classify_fixed(const tg_domain *domain, const char *original, void *buf, size_t available);
const char *tg_result_get(tg_result *result, const char *key);
void tg_result_free(tg_result *result);


tg_pattern *tg_pattern_alloc();
tg_pattern *tg_pattern_get(tg_domain *domain);
tg_pattern *tg_pattern_create(tg_pattern *pattern, jsmntok_t *tokens);
size_t tg_pattern_matched_length(tg_pattern *pattern, tg_list *matched_tokens);
long tg_pattern_rank(tg_pattern *pattern);
void tg_pattern_free(tg_pattern *pattern);


tg_list *tg_transformer_compile(jsmntok_t *tokens);
void tg_transformer_free(tg_transformer *transformer);


void tg_memalloc_init(tg_memalloc *memalloc, void *buf, size_t available);
tg_attributes *tg_memalloc_bootstrap(void *buf, size_t available, size_t keys);
void *tg_memalloc_malloc(tg_memalloc *memalloc, size_t size);
void tg_memalloc_add_free(tg_memalloc *memalloc, void *ptr);


void tg_attributes_json_index(tg_domain *domain, tg_jsonfile *json_file);
tg_attributes *tg_attributes_build(tg_domain *domain, const char *pattern_id);
tg_attributes *tg_attributes_alloc(size_t keys);
inline size_t tg_attributes_size(size_t keys);
void tg_attributes_init(tg_attributes *attributes, size_t keys);
void tg_attributes_free(tg_attributes *attributes);


#endif	/* _TEXTGLASS_H_INCLUDED_ */
