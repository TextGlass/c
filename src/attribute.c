#include "textglass.h"

static tg_attribute *tg_attribute_alloc();

void tg_attribute_json_index(tg_domain *domain, tg_jsonfile *json_file)
{
	jsmntok_t *tokens, *token;
	int i;

	if(!json_file)
	{
		return;
	}

	assert(json_file->magic == TG_JSONFILE_MAGIC);
	assert(domain && domain->magic == TG_DOMAIN_MAGIC);
	assert(domain->attribute_index && domain->attribute_index->magic == TG_HASHTABLE_MAGIC);

	tokens = tg_json_get(json_file->tokens, "attributes");

	if(TG_JSON_IS_OBJECT(tokens))
	{
		tg_printd(2, "Found %d attribute(s) in file\n", tokens->size);

		for(i = 1; i < tokens[0].skip; i++)
		{
			token = &tokens[i];

			tg_printd(3, "Found attribute: %s\n", token->str);

			tg_hashtable_set(domain->attribute_index, token->str, &tokens[i + 1]);

			i+= tokens[i].skip;
		}
	}
}

int tg_attribute_build(tg_domain *domain, tg_pattern *pattern)
{
	tg_list *keys, *values, *transformer_keys, *transformers;
	jsmntok_t *tokens;

	assert(pattern && pattern->magic == TG_PATTERN_MAGIC);
	assert(domain && domain->magic == TG_DOMAIN_MAGIC);
	assert(domain->attribute_index && domain->attribute_index->magic == TG_HASHTABLE_MAGIC);

	keys = tg_list_alloc(20, NULL);
	values = tg_list_alloc(20, NULL);
	transformer_keys = tg_list_alloc(10, NULL);
	transformers = tg_list_alloc(10, (TG_FREE)&tg_list_free);

	tokens = tg_hashtable_get(domain->attribute_index, pattern->pattern_id);

	if(TG_JSON_IS_OBJECT(tokens))
	{
		tg_printd(4, "Building attributes for %s\n", pattern->pattern_id);
	}

	pattern->attribute = tg_attribute_alloc(1, 1);

	pattern->attribute->pattern = (struct tg_pattern*)pattern;
	pattern->attribute->transformers = transformers;

	tg_list_free(keys);
	tg_list_free(values);
	tg_list_free(transformer_keys);

	return 0;
}

static tg_attribute *tg_attribute_alloc(size_t keys, size_t values)
{
	tg_attribute *attribute;

	attribute = calloc(1, sizeof(tg_attribute) + (sizeof(char*) * (keys + values)));

	assert(attribute);

	attribute->magic = TG_ATTRIBUTE_MAGIC;
	attribute->malloc = 1;
	attribute->key_len = keys;
	attribute->value_len = values;
	attribute->keys = attribute->buf;
	attribute->values = &attribute->buf[attribute->key_len];
	attribute->transformers = NULL;

	return attribute;
}

void tg_attribute_free(tg_attribute *attribute)
{
	assert(attribute && attribute->magic == TG_ATTRIBUTE_MAGIC);

	attribute->magic = 0;

	tg_list_free(attribute->transformers);

	if(attribute->malloc)
	{
		free(attribute);
	}
}


