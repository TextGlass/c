#include "textglass.h"

static tg_domain *tg_domain_init(tg_jsonfile *pattern, tg_jsonfile *attribute,
				 tg_jsonfile *pattern_patch, tg_jsonfile *attribute_patch);
static tg_list *tg_domain_list_get(tg_domain *domain, void (*free)(void *item));
static long tg_domain_create_pindex(tg_domain *domain, jsmntok_t *tokens);

tg_domain *tg_domain_load(const char *pattern, const char *attribute,
			  const char *pattern_patch, const char *attribute_patch)
{
	tg_jsonfile *pattern_file = NULL;
	tg_jsonfile *attribute_file = NULL;
	tg_jsonfile *pattern_patch_file = NULL;
	tg_jsonfile *attribute_patch_file = NULL;

	//PARSE ATTRIBUTE FILE

	tg_printd(1, "Pattern file: %s\n", pattern);

	pattern_file = tg_jsonfile_get(pattern);

	if(!pattern_file || strcmp(pattern_file->type, "pattern"))
	{
		fprintf(stderr, "Invalid pattern file\n");
		goto derror;
	}

	//PARSE ATTRIBUTE FILE

	if(attribute)
	{
		tg_printd(1, "Attribute file: %s\n", attribute);

		attribute_file = tg_jsonfile_get(attribute);

		if(!attribute_file || strcmp(attribute_file->type, "attribute") ||
			strcmp(attribute_file->domain, pattern_file->domain) ||
			strcmp(attribute_file->domain_version, pattern_file->domain_version))
		{
			fprintf(stderr, "Invalid attribute file\n");
			goto derror;
		}
	}

	//PARSE PATTERN PATCH FILE

	if(pattern_patch)
	{
		tg_printd(1, "Pattern patch file: %s\n", pattern_patch);

		pattern_patch_file = tg_jsonfile_get(pattern_patch);

		if(!pattern_patch_file || strcmp(pattern_patch_file->type, "patternPatch") ||
			strcmp(pattern_patch_file->domain, pattern_file->domain) ||
			strcmp(pattern_patch_file->domain_version, pattern_file->domain_version))
		{
			fprintf(stderr, "Invalid pattern patch file\n");
			goto derror;
		}
	}

	//PARSE ATTRIBUTE PATCH FILE

	if(attribute_patch)
	{
		tg_printd(1, "Attribute patch file: %s\n", attribute_patch);

		attribute_patch_file = tg_jsonfile_get(attribute_patch);

		if(!attribute_patch_file || strcmp(attribute_patch_file->type, "attributePatch") ||
			strcmp(attribute_patch_file->domain, pattern_file->domain) ||
			strcmp(attribute_patch_file->domain_version, pattern_file->domain_version))
		{
			fprintf(stderr, "Invalid attribute patch file\n");
			goto derror;
		}
	}

	return tg_domain_init(pattern_file, attribute_file, pattern_patch_file, attribute_patch_file);

derror:
	tg_jsonfile_free(pattern_file);
	tg_jsonfile_free(attribute_file);
	tg_jsonfile_free(pattern_patch_file);
	tg_jsonfile_free(attribute_patch_file);

	return NULL;
}

static tg_domain *tg_domain_init(tg_jsonfile *pattern, tg_jsonfile *attribute,
				 tg_jsonfile *pattern_patch, tg_jsonfile *attribute_patch)
{
	tg_domain *domain;
	jsmntok_t *token, *tokens, *norm, *patch;
	const char *field;
	long count, count2;
	long i;

	assert(pattern);

	domain = calloc(1, sizeof(tg_domain));

	assert(domain);

	domain->magic = TG_DOMAIN_MAGIC;

	domain->pattern = pattern;
	domain->attribute = attribute;
	domain->pattern_patch = pattern_patch;
	domain->attribute_patch = attribute_patch;

	domain->domain = pattern->domain;
	domain->domain_version = pattern->domain_version;

	//LOAD THE INPUT PARSERS

	norm = tg_json_get(domain->pattern->tokens, "inputParser");
	patch = NULL;

	if(domain->pattern_patch)
	{
		patch = tg_json_get(domain->pattern_patch->tokens, "inputParser");
	}

	//INPUT TRANSFORMERS

	tokens = tg_json_get(patch, "transformers");

	if(!TG_JSON_IS_ARRAY(tokens))
	{
		tokens = tg_json_get(norm, "transformers");
	}

	if(TG_JSON_IS_ARRAY(tokens))
	{
		domain->input_transformers = tg_transformer_compile(tokens);

		if(!domain->input_transformers)
		{
			goto derror;
		}

		tg_printd(1, "Found %zu transformer(s)\n", domain->input_transformers->size);

		if(!domain->input_transformers->size)
		{
			tg_list_free(domain->input_transformers);
			domain->input_transformers = NULL;
		}
	}

	//TOKEN SEPERATORS

	tokens = tg_json_get(patch, "tokenSeperators");

	if(!TG_JSON_IS_ARRAY(tokens))
	{
		tokens = tg_json_get(norm, "tokenSeperators");
	}

	if(TG_JSON_IS_ARRAY(tokens))
	{
		domain->token_seperator_len = tokens->size;
		domain->token_seperators = malloc(sizeof(char*) * domain->token_seperator_len);

		assert(domain->token_seperators);

		for(i = 0; i < tokens->size; i++)
		{
			token = &tokens[i + 1];
			domain->token_seperators[i] = token->str;

			tg_printd(2, "Found tokenSeperators: '%s'\n", token->str);
		}

		tg_printd(1, "Found %d tokenSeperator(s)\n", domain->token_seperator_len);
	}

	//NGRAM CONCAT SIZE

	domain->ngram_size = 1;

	field = tg_json_get_str(patch, "ngramConcatSize");

	if(!field)
	{
		field = tg_json_get_str(norm, "ngramConcatSize");
	}

	if(field)
	{
		i = atol(field);

		if(i < 1)
		{
			fprintf(stderr, "Invalid ngramConcatSize\n");
			goto derror;
		}

		domain->ngram_size = i;

		tg_printd(1, "Found ngramConcatSize: %lu\n", domain->ngram_size);
	}

	//DEFAULT PATTERN ID

	patch = NULL;

	if(domain->pattern_patch)
	{
		patch = tg_json_get(domain->pattern_patch->tokens, "patternSet");

		domain->default_id = tg_json_get_str(patch, "defaultId");

		patch = tg_json_get(patch, "patterns");
	}

	norm = tg_json_get(domain->pattern->tokens, "patternSet");

	if(!domain->default_id)
	{
		domain->default_id = tg_json_get_str(norm, "defaultId");
	}

	norm = tg_json_get(norm, "patterns");

	if(domain->default_id)
	{
		tg_printd(2, "Found defaultId: %s\n", domain->default_id);
	}

	//ATTRIBUTE INDEX

	domain->attribute_index = tg_hashtable_alloc(100, NULL);

	tg_attributes_json_index(domain, domain->pattern);
	tg_attributes_json_index(domain, domain->pattern_patch);
	tg_attributes_json_index(domain, domain->attribute);
	tg_attributes_json_index(domain, domain->attribute_patch);

	tg_printd(1, "Found %zu attribute(s)\n", tg_hashtable_size(domain->attribute_index));

	if(domain->default_id)
	{
		domain->default_attributes = tg_attributes_build(domain, domain->default_id);

		if(!domain->default_attributes)
		{
			goto derror;
		}
	}

	//PATTERN INDEX

	count = 0;

	if(TG_JSON_IS_ARRAY(norm))
	{
		count += norm[0].size;
	}

	if(TG_JSON_IS_ARRAY(patch))
	{
		count += patch[0].size;
	}

	domain->patterns = tg_hashtable_alloc(count + 100, (TG_FREE)&tg_list_free);

	tg_printd(3, "Pattern hash size: %ld\n", count);

	domain->pattern_slab_size = count;
	domain->pattern_slab_pos = 0;

	domain->pattern_slab = calloc(domain->pattern_slab_size, sizeof(tg_pattern));

	assert(domain->pattern_slab);

	domain->list_slab_size = count;
	domain->list_slab_pos = 0;

	domain->list_slab = calloc(domain->list_slab_size, sizeof(tg_list));

	assert(domain->list_slab);

	count = tg_domain_create_pindex(domain, norm);

	if(count < 1)
	{
		goto derror;
	}

	count2 = tg_domain_create_pindex(domain, patch);

	if(count2 < 0)
	{
		goto derror;
	}

	tg_printd(1, "Found %ld pattern(s)\n", count + count2);

	tg_hashtable_free(domain->attribute_index);
	domain->attribute_index = NULL;

	tg_jsonfile_free_tokens(domain->pattern);
	tg_jsonfile_free_tokens(domain->attribute);
	tg_jsonfile_free_tokens(domain->pattern_patch);
	tg_jsonfile_free_tokens(domain->attribute_patch);

	return domain;

derror:
	tg_domain_free(domain);

	return NULL;
}

static long tg_domain_create_pindex(tg_domain *domain, jsmntok_t *tokens)
{
	jsmntok_t *token;
	tg_pattern *pattern;
	tg_list *list;
	tg_list_item *item;
	long count = 0;
	long i;

	assert(domain && domain->magic == TG_DOMAIN_MAGIC);
	
	if(TG_JSON_IS_ARRAY(tokens))
	{
		for(i = 1; i < tokens[0].skip; i += tokens[i].skip)
		{
			token = &tokens[i];

			pattern = tg_pattern_get(domain);

			pattern = tg_pattern_create(pattern, token);

			if(!pattern)
			{
				return -1;
			}

			pattern->attribute = tg_attributes_build(domain, pattern->pattern_id);

			if(!pattern->attribute)
			{
				return -1;
			}

			TG_LIST_FOREACH(&pattern->pattern_tokens, item)
			{
				list = tg_hashtable_get(domain->patterns, (char*)item->value);

				if(!list)
				{
					list = tg_domain_list_get(domain, (TG_FREE)&tg_pattern_free);
					tg_hashtable_set(domain->patterns, (char*)item->value, list);
				}

				assert(list->magic == TG_LIST_MAGIC);

				tg_list_add(list, pattern);

				pattern->ref_count++;

				tg_printd(4, "Adding %s to pindex '%s'\n", pattern->pattern_id, (char*)item->value);

				count++;
			}
		}
	}

	return count;
}

void tg_domain_free(tg_domain *domain)
{
	if(!domain)
	{
		return;
	}

	assert(domain->magic == TG_DOMAIN_MAGIC);

	if(domain->patterns)
	{
		tg_hashtable_free(domain->patterns);
	}

	if(domain->list_slab)
	{
		free(domain->list_slab);
	}

	if(domain->pattern_slab)
	{
		free(domain->pattern_slab);
	}

	if(domain->token_seperators)
	{
		free(domain->token_seperators);
	}

	if(domain->attribute_index)
	{
		tg_hashtable_free(domain->attribute_index);
	}

	if(domain->default_attributes)
	{
		tg_attributes_pattern_free(domain->default_attributes);
	}

	if(domain->input_transformers)
	{
		tg_list_free(domain->input_transformers);
	}

	tg_jsonfile_free(domain->pattern);
	tg_jsonfile_free(domain->attribute);
	tg_jsonfile_free(domain->pattern_patch);
	tg_jsonfile_free(domain->attribute_patch);

	domain->pattern = NULL;
	domain->attribute = NULL;
	domain->pattern_patch = NULL;
	domain->attribute_patch = NULL;

	domain->magic = 0;

	free(domain);
}

static tg_list *tg_domain_list_get(tg_domain *domain, void (*free)(void *item))
{
	tg_list *list;

	assert(domain && domain->magic == TG_DOMAIN_MAGIC);

	if(domain->list_slab_pos >= domain->list_slab_size)
	{
		return tg_list_alloc(0, free);
	}

	list = &domain->list_slab[domain->list_slab_pos];

	tg_list_init(list, 0, free);

	domain->list_slab_pos++;

	return list;
}
