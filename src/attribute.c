#include "textglass.h"

static tg_attribute *tg_attribute_alloc();

void tg_attribute_json_index(tg_domain *domain, tg_jsonfile *json_file)
{
	jsmntok_t *tokens, *token;
	long i;

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

		for(i = 1; i < tokens[0].skip; i += tokens[i].skip)
		{
			token = &tokens[i];

			tg_printd(3, "Found attribute: %s\n", token->str);

			tg_hashtable_set(domain->attribute_index, token->str, &tokens[i + 1]);
		}
	}
}

tg_attribute *tg_attribute_build(tg_domain *domain, const char *pattern_id)
{
	tg_attribute *attribute = NULL;
	jsmntok_t *ptokens, *tokens, *key, *value;
	tg_list *keys, *values;
	tg_list *transformer_keys, *transformers, *attribute_transformer;
	tg_list *default_values;
	tg_list_item *item;
	const char *default_value, *current;
	size_t pos;
	long i;

	assert(domain && domain->magic == TG_DOMAIN_MAGIC);
	assert(domain->attribute_index && domain->attribute_index->magic == TG_HASHTABLE_MAGIC);
	assert(pattern_id);

	keys = tg_list_alloc(20, NULL);
	values = tg_list_alloc(20, NULL);
	transformer_keys = tg_list_alloc(10, NULL);
	transformers = tg_list_alloc(10, (TG_FREE)&tg_list_free);
	default_values = tg_list_alloc(10, NULL);

	//ATTRIBUTES

	ptokens = tg_hashtable_get(domain->attribute_index, pattern_id);
	current = pattern_id;

	while(current)
	{
		tg_printd(4, "Building attributes for %s\n", current);

		tokens = tg_json_get(ptokens, "attributes");

		for(i = 1; TG_JSON_IS_OBJECT(tokens) && i < tokens[0].skip; i += tokens[i].skip)
		{
			key = &tokens[i];

			if(key->size != 1)
			{
				goto aerror;
			}

			value = &tokens[i + 1];

			if(current != pattern_id && tg_list_index_str(keys, key->str) >= 0)
			{
				continue;
			}

			tg_list_add(keys, (void*)key->str);
			tg_list_add(values, (void*)value->str);

			tg_printd(5, "Found attribute: '%s'='%s'\n", key->str, value->str);
		}


		tokens = tg_json_get(ptokens, "attributeTransformers");

		for(i = 1; TG_JSON_IS_OBJECT(tokens) && i < tokens[0].skip; i += tokens[i].skip)
		{
			key = &tokens[i];

			if(key->size != 1)
			{
				goto aerror;
			}

			value = &tokens[i + 1];

			if(!TG_JSON_IS_OBJECT(value))
			{
				goto aerror;
			}

			if(current != pattern_id && tg_list_index_str(transformer_keys, key->str) >= 0)
			{
				continue;
			}

			default_value = tg_json_get_str(value, "defaultValue");

			if(!default_value)
			{
				tg_list_add(default_values, "");
			}
			else
			{
				tg_list_add(default_values, (void*)default_value);
			}

			value = tg_json_get(value, "transformers");

			if(!TG_JSON_IS_ARRAY(value))
			{
				goto aerror;
			}

			attribute_transformer = tg_transformer_compile(value);

			if(!attribute_transformer)
			{
				goto aerror;
			}

			tg_list_add(transformer_keys, (void*)key->str);
			tg_list_add(transformers, attribute_transformer);

			tg_printd(5, "Found transformed attribute: '%s':%zu\n",
				key->str, attribute_transformer->size);
		}

		current = tg_json_get_str(ptokens, "parentId");

		if(current)
		{
			ptokens = tg_hashtable_get(domain->attribute_index, current);
		}
		else
		{
			ptokens = NULL;
		}
	}

	assert(keys->size == values->size);
	assert(transformer_keys->size == transformers->size);
	assert(transformers->size == default_values->size);

	attribute = tg_attribute_alloc(keys->size + transformer_keys->size, values->size);

	attribute->pattern_id = pattern_id;
	attribute->transformers = transformers;

	pos = 0;

	TG_LIST_FOREACH(keys, item)
	{
		attribute->keys[pos++] = (char*)item->value;
	}

	TG_LIST_FOREACH(transformer_keys, item)
	{
		attribute->keys[pos++] = (char*)item->value;
	}

	assert(pos == attribute->key_len);

	pos = 0;

	TG_LIST_FOREACH(values, item)
	{
		attribute->values[pos++] = (char*)item->value;
	}

	assert(pos == attribute->value_len);

	pos = 0;

	TG_LIST_FOREACH(default_values, item)
	{
		attribute->default_values[pos++] = (char*)item->value;
	}

	assert(pos == attribute->transformers->size);

	tg_list_free(keys);
	tg_list_free(values);
	tg_list_free(transformer_keys);
	tg_list_free(default_values);

	return attribute;

aerror:
	tg_list_free(keys);
	tg_list_free(values);
	tg_list_free(transformer_keys);
	tg_list_free(transformers);
	tg_list_free(default_values);

	if(attribute)
	{
		attribute->transformers = NULL;
		tg_attribute_free(attribute);
	}

	return NULL;
}

static tg_attribute *tg_attribute_alloc(size_t keys, size_t values)
{
	tg_attribute *attribute;

	assert(keys >= values);

	attribute = calloc(1, sizeof(tg_attribute) + (sizeof(char*) * (keys + values)) +
			(sizeof(char*) * (keys - values)));

	assert(attribute);

	attribute->magic = TG_ATTRIBUTE_MAGIC;
	attribute->malloc = 1;
	attribute->key_len = keys;
	attribute->value_len = values;
	attribute->keys = attribute->buf;
	attribute->values = &attribute->buf[attribute->key_len];
	attribute->default_values = &attribute->buf[attribute->key_len + attribute->value_len];
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