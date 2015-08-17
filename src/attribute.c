#include "textglass.h"

static void tg_attribute_init(tg_attribute *attribute);

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

void tg_attribute_build(tg_domain *domain, tg_pattern *pattern)
{
	jsmntok_t *tokens;

	assert(pattern && pattern->magic == TG_PATTERN_MAGIC);
	assert(domain && domain->magic == TG_DOMAIN_MAGIC);
	assert(domain->attribute_index && domain->attribute_index->magic == TG_HASHTABLE_MAGIC);

	tg_attribute_init(&pattern->attribute);

	pattern->attribute.pattern = (struct tg_pattern*)pattern;

	tokens = tg_hashtable_get(domain->attribute_index, pattern->pattern_id);

	if(!TG_JSON_IS_OBJECT(tokens))
	{
		tg_printd(4, "Building default attributes for %s\n", pattern->pattern_id);
	}
	else
	{
		tg_printd(4, "Building attributes for %s\n", pattern->pattern_id);
	}
}

static void tg_attribute_init(tg_attribute *attribute)
{
	assert(attribute);

	memset(attribute, 0, sizeof(tg_attribute));

	attribute->magic = TG_ATTRIBUTE_MAGIC;

	tg_list_init(&attribute->transformers, 0, (TG_FREE)&tg_list_free);
}

void tg_attribute_free(tg_attribute *attribute)
{
	assert(attribute && attribute->magic == TG_ATTRIBUTE_MAGIC);

	attribute->magic = 0;

	tg_list_free(&attribute->transformers);

	if(attribute->malloc)
	{
		free(attribute);
	}
}


