#include "textglass.h"

tg_pattern *tg_pattern_alloc()
{
	tg_pattern *pattern;

	pattern = malloc(sizeof(tg_pattern));

	assert(pattern);

	pattern->magic = TG_PATTERN_MAGIC;
	pattern->pattern_token_init = 0;
	pattern->malloc = 1;
	pattern->ref_count = 0;

	return pattern;
}

tg_pattern *tg_pattern_get(tg_domain *domain)
{
	tg_pattern *pattern;

	assert(domain && domain->magic == TG_DOMAIN_MAGIC);

	if(domain->pattern_slab_pos >= domain->pattern_slab_size)
	{
		return tg_pattern_alloc();
	}

	pattern = &domain->pattern_slab[domain->pattern_slab_pos];

	pattern->magic = TG_PATTERN_MAGIC;
	pattern->pattern_token_init = 0;
	pattern->malloc = 0;
	pattern->ref_count = 0;

	domain->pattern_slab_pos++;

	return pattern;
}

tg_pattern *tg_pattern_create(tg_pattern *pattern, jsmntok_t *tokens)
{
	const char *value;
	jsmntok_t *token;
	int i;

	assert(pattern && pattern->magic == TG_PATTERN_MAGIC);

	//PATTERN ID

	pattern->pattern_id = tg_json_get_str(tokens, "patternId");

	if(!pattern->pattern_id || !*pattern->pattern_id)
	{
		fprintf(stderr, "Invalid patternId\n");
		goto perror;
	}

	tg_printd(3, "Found patternId: %s\n", pattern->pattern_id);

	//PATTERN TYPE

	value = tg_json_get_str(tokens, "patternType");

	if(!value)
	{
		fprintf(stderr, "Invalid patternType]\n");
		goto perror;
	}
	else if(!strcmp(value, "Simple"))
	{
		pattern->pattern_type = TG_PATTERN_SIMPLE;
	}
	else if(!strcmp(value, "SimpleAnd"))
	{
		pattern->pattern_type = TG_PATTERN_AND;
	}
	else if(!strcmp(value, "SimpleOrderedAnd"))
	{
		pattern->pattern_type = TG_PATTERN_ORDERED_AND;
	}
	else
	{
		fprintf(stderr, "Invalid patternType\n");
		goto perror;
	}

	tg_printd(3, "  Found patternType: %s\n", value);

	//PATTERN TOKENS

	tg_list_init(&pattern->pattern_tokens, 0, NULL);
	pattern->pattern_token_init = 1;

	token = tg_json_get(tokens, "patternTokens");

	if(TG_JSON_IS_ARRAY(token))
	{
		for(i = 0; i < token->size; i++)
		{
			tg_printd(3, "  Found patternToken: '%s'\n", token[i + 1].str);

			tg_list_add(&pattern->pattern_tokens, (void*)token[i + 1].str);
		}
	}
	else
	{
		fprintf(stderr, "Invalid patternTokens\n");
		goto perror;
	}

	//RANK TYPE

	value = tg_json_get_str(tokens, "rankType");

	if(!value)
	{
		fprintf(stderr, "Invalid rankType\n");
		goto perror;
	}
	else if(!strcmp(value, "None"))
	{
		pattern->pattern_type = TG_RANKTYPE_NONE;
	}
	else if(!strcmp(value, "Weak"))
	{
		pattern->pattern_type = TG_RANKTYPE_WEAK;
	}
	else if(!strcmp(value, "Strong"))
	{
		pattern->pattern_type = TG_RANKTYPE_STRONG;
	}
	else
	{
		fprintf(stderr, "Invalid rankType\n");
		goto perror;
	}

	tg_printd(3, "  Found rankType: %s\n", value);

	//RANK VALUE

	pattern->rank_value = 0;

	tg_printd(3, "  Found rankValue: %d\n", pattern->rank_value);

	return pattern;

perror:
	pattern->ref_count = 1;

	tg_pattern_free(pattern);

	return NULL;
}

void tg_pattern_free(tg_pattern *pattern)
{
	assert(pattern && pattern->magic == TG_PATTERN_MAGIC);

	assert(pattern->ref_count > 0);

	if(pattern->ref_count > 1)
	{
		pattern->ref_count--;
		return;
	}

	if(pattern->pattern_token_init)
	{
		tg_list_free(&pattern->pattern_tokens);
	}

	pattern->magic = 0;

	if(pattern->malloc)
	{
		free(pattern);
	}
}
