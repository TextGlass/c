#include "textglass.h"

static void tg_pattern_init(tg_pattern *pattern);

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
		fprintf(stderr, "Invalid patternType\n");
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

	tg_printd(4, "Found patternType: %s\n", value);

	//PATTERN TOKENS

	tg_list_init(&pattern->pattern_tokens, 0, NULL);
	pattern->pattern_tokens_init = 1;

	token = tg_json_get(tokens, "patternTokens");

	if(TG_JSON_IS_ARRAY(token))
	{
		for(i = 0; i < token->size; i++)
		{
			tg_printd(4, "Found patternToken: '%s'\n", token[i + 1].str);

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
		pattern->rank_type = TG_RANKTYPE_NONE;
	}
	else if(!strcmp(value, "Weak"))
	{
		pattern->rank_type = TG_RANKTYPE_WEAK;
	}
	else if(!strcmp(value, "Strong"))
	{
		pattern->rank_type = TG_RANKTYPE_STRONG;
	}
	else
	{
		fprintf(stderr, "Invalid rankType\n");
		goto perror;
	}

	tg_printd(4, "Found rankType: %s\n", value);

	//RANK VALUE

	pattern->rank_value = 0;

	value = tg_json_get_str(tokens, "rankValue");

	if(value)
	{
		pattern->rank_value = atoi(value);

		if(pattern->rank_value > 1000 || pattern->rank_value < -1000)
		{
			fprintf(stderr, "Invalid rankValue\n");
			goto perror;
		}
	}

	tg_printd(4, "Found rankValue: %d\n", pattern->rank_value);

	return pattern;

perror:
	pattern->ref_count = 1;

	tg_pattern_free(pattern);

	return NULL;
}

size_t tg_pattern_matched_length(tg_pattern *pattern, tg_list *matched_tokens)
{
	long last_found = -1, found;
	size_t length = 0;
	tg_list_item *item;
	char *pattern_token;

	assert(pattern && pattern->magic == TG_PATTERN_MAGIC);
	assert(matched_tokens && matched_tokens->magic == TG_LIST_MAGIC);

	TG_LIST_FOREACH(&pattern->pattern_tokens, item)
	{
		pattern_token = (char*)item->value;

		found = tg_list_index_str(matched_tokens, pattern_token);

		if(found == -1 && (pattern->pattern_type == TG_PATTERN_AND ||
			pattern->pattern_type == TG_PATTERN_ORDERED_AND))
		{
			return 0;
		}

		if(found >= 0)
		{
			length += strlen(pattern_token);
		}

		if(pattern->pattern_type == TG_PATTERN_ORDERED_AND)
		{
			if(found <= last_found)
			{
				return 0;
			}
			else
			{
				last_found = found;
			}
		}
	}

	return length;
}

int tg_pattern_rank(tg_pattern *pattern)
{
	int rank;

	if(!pattern)
	{
		return -10000000;
	}

	assert(pattern && pattern->magic == TG_PATTERN_MAGIC);

	rank = pattern->rank_value;

	if(pattern->rank_type == TG_RANKTYPE_WEAK)
	{
		rank += 100000;
	}
	else if(pattern->rank_type == TG_RANKTYPE_STRONG)
	{
		return 10000000;
	}

	return rank;
}

tg_pattern *tg_pattern_alloc()
{
	tg_pattern *pattern;

	pattern = malloc(sizeof(tg_pattern));

	assert(pattern);

	tg_pattern_init(pattern);

	pattern->malloc = 1;

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

	tg_pattern_init(pattern);

	domain->pattern_slab_pos++;

	return pattern;
}

static void tg_pattern_init(tg_pattern *pattern)
{
	assert(pattern);

	pattern->magic = TG_PATTERN_MAGIC;
	pattern->pattern_tokens_init = 0;
	pattern->malloc = 0;
	pattern->ref_count = 0;
	pattern->attribute = NULL;
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

	if(pattern->pattern_tokens_init)
	{
		tg_list_free(&pattern->pattern_tokens);
	}

	if(pattern->attribute)
	{
		tg_attribute_free(pattern->attribute);
	}

	pattern->magic = 0;

	if(pattern->malloc)
	{
		free(pattern);
	}
}
