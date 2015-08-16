#include "textglass.h"

static tg_attribute *tg_attribute_alloc();

void tg_attribute_json_index(tg_hashtable *index, tg_jsonfile *json_file)
{
	jsmntok_t *tokens, *token;
	int i;

	if(!json_file)
	{
		return;
	}

	assert(json_file->magic == TG_JSONFILE_MAGIC);

	tokens = tg_json_get(json_file->tokens, "attributes");

	if(TG_JSON_IS_OBJECT(tokens))
	{
		tg_printd(2, "Found %d attribute(s) in file\n", tokens->size);

		for(i = 1; i < tokens[0].skip; i++)
		{
			token = &tokens[i];

			tg_printd(3, "Found attribute: %s\n", token->str);

			tg_hashtable_set(index, token->str, token);

			i+= tokens[i].skip;
		}
	}
}

static tg_attribute *tg_attribute_alloc()
{
	tg_attribute *attribute;

	attribute = malloc(sizeof(tg_attribute));

	assert(attribute);

	attribute->magic = TG_ATTRIBUTE_MAGIC;
	attribute->malloc = 1;

	return attribute;
}

tg_attribute *tg_attribute_get(tg_domain *domain)
{
	tg_attribute *attribute;

	assert(domain && domain->magic == TG_DOMAIN_MAGIC);

	if(domain->attribute_slab_pos >= domain->attribute_slab_size)
	{
		return tg_attribute_alloc();
	}

	attribute = &domain->attribute_slab[domain->attribute_slab_pos];

	attribute->magic = TG_ATTRIBUTE_MAGIC;
	attribute->malloc = 0;

	domain->attribute_slab_pos++;

	return attribute;
}

void tg_attribute_free(tg_attribute *attribute)
{
	assert(attribute && attribute->magic == TG_ATTRIBUTE_MAGIC);

	attribute->magic = 0;

	if(attribute->malloc)
	{
		free(attribute);
	}
}


