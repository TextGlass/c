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

#include "textglass.h"

void tg_attributes_json_index(tg_domain *domain, tg_jsonfile *json_file)
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

tg_attributes *tg_attributes_build(tg_domain *domain, const char *pattern_id)
{
	tg_attributes *attributes = NULL;
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

	attributes = tg_attributes_alloc(keys->size + transformer_keys->size);

	attributes->pattern_id = pattern_id;
	attributes->transformers = transformers;

	pos = 0;

	TG_LIST_FOREACH(keys, item)
	{
		attributes->keys[pos++] = (char*)item->value;
	}

	TG_LIST_FOREACH(transformer_keys, item)
	{
		attributes->keys[pos++] = (char*)item->value;
	}

	assert(pos == attributes->key_len);

	pos = 0;

	TG_LIST_FOREACH(values, item)
	{
		attributes->values[pos++] = (char*)item->value;
	}

	TG_LIST_FOREACH(default_values, item)
	{
		attributes->values[pos++] = (char*)item->value;
	}

	assert(pos == attributes->key_len);

	if(!attributes->transformers->size)
	{
		tg_list_free(attributes->transformers);
		attributes->transformers = NULL;
	}

	tg_list_free(keys);
	tg_list_free(values);
	tg_list_free(transformer_keys);
	tg_list_free(default_values);

	return attributes;

aerror:
	tg_list_free(keys);
	tg_list_free(values);
	tg_list_free(transformer_keys);
	tg_list_free(transformers);
	tg_list_free(default_values);

	if(attributes)
	{
		attributes->transformers = NULL;
		tg_attributes_free(attributes);
	}

	return NULL;
}

tg_attributes *tg_attributes_alloc(size_t keys)
{
	tg_attributes *attributes;

	attributes = calloc(1, sizeof(tg_attributes) + (sizeof(char*) * keys * 2));

	assert(attributes);

	attributes->magic = TG_ATTRIBUTES_MAGIC;
	attributes->key_len = keys;
	attributes->keys = attributes->buf;
	attributes->values = &attributes->buf[attributes->key_len];

	return attributes;
}

void tg_attributes_free(tg_attributes *attributes)
{
	if(!attributes)
	{
		return;
	}

	assert(attributes && attributes->magic == TG_ATTRIBUTES_MAGIC);

	attributes->magic = 0;

	tg_list_free(attributes->free_list);
	tg_list_free(attributes->transformers);

	free(attributes);
}
