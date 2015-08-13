#include "textglass.h"
#include "list.h"

static tg_domain *tg_domain_init(tg_jsonfile *pattern, tg_jsonfile *attribute,
		tg_jsonfile *pattern_patch, tg_jsonfile *attribute_patch);

tg_domain *tg_domain_load(const char *pattern, const char *attribute,
		const char *pattern_patch, const char *attribute_patch)
{
	tg_jsonfile *pattern_file = NULL;
	tg_jsonfile *attribute_file = NULL;
	tg_jsonfile *pattern_patch_file = NULL;
	tg_jsonfile *attribute_patch_file = NULL;
	tg_domain *domain = NULL;

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
		if(!attribute_file  || strcmp(attribute_file->type, "attribute") ||
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
		if(!pattern_patch_file  || strcmp(pattern_patch_file->type, "patternPatch")  ||
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
		if(!attribute_patch_file  || strcmp(attribute_patch_file->type, "attributePatch" ) ||
			strcmp(attribute_patch_file->domain, pattern_file->domain) ||
			strcmp(attribute_patch_file->domain_version, pattern_file->domain_version))
		{
			fprintf(stderr, "Invalid attribute patch file\n");
			goto derror;
		}
	}

	domain = tg_domain_init(pattern_file, attribute_file, pattern_patch_file, attribute_patch_file);

	return domain;

derror:
	tg_domain_free(domain);

	return NULL;
}

static tg_domain *tg_domain_init(tg_jsonfile *pattern, tg_jsonfile *attribute,
		tg_jsonfile *pattern_patch, tg_jsonfile *attribute_patch)
{
	tg_domain *domain;
	jsmntok_t *token, *tokens, *norm, *patch;
	tg_list *list;
	tg_pattern *pattern_obj;
	int i;
	size_t count;

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

	if(count < 100)
	{
		count = 100;
	}
	
	domain->patterns = tg_hashtable_init(count, (TG_FREE)&tg_list_free);

	tg_printd(3, "Pattern hash size: %zu\n", count);

	count = 0;

	if(TG_JSON_IS_ARRAY(norm))
	{
		for(i = 1; i < norm[0].skip; i++)
		{
			tokens = &norm[i];

			pattern_obj = tg_pattern_create(tokens);

			if(!pattern_obj)
			{
				goto derror;
			}

			list = tg_hashtable_get(domain->patterns, pattern_obj->pattern_id);

			if(!list)
			{
				list = tg_list_init(2, (TG_FREE)&tg_pattern_free);
				tg_hashtable_set(domain->patterns, pattern_obj->pattern_id, list);
			}

			tg_list_add(list, pattern_obj);

			count++;

			i+= norm[i].skip;
		}
	}

	if(TG_JSON_IS_ARRAY(patch))
	{
		for(i = 1; i < patch[0].skip; i++)
		{
			tokens = &patch[i];

			pattern_obj = tg_pattern_create(tokens);

			if(!pattern_obj)
			{
				goto derror;
			}

			list = tg_hashtable_get(domain->patterns, pattern_obj->pattern_id);

			if(!list)
			{
				list = tg_list_init(2, (TG_FREE)&tg_pattern_free);
				tg_hashtable_set(domain->patterns, pattern_obj->pattern_id, list);
			}

			tg_list_add(list, pattern_obj);

			count++;

			i+= patch[i].skip;
		}
	}

	tg_printd(1, "Found %zu pattern(s)\n", count);

	tg_jsonfile_free_tokens(domain->pattern);
	tg_jsonfile_free_tokens(domain->attribute);
	tg_jsonfile_free_tokens(domain->pattern_patch);
	tg_jsonfile_free_tokens(domain->attribute_patch);

	return domain;

derror:
	tg_domain_free(domain);

	return NULL;
}

void tg_domain_free(tg_domain *domain)
{
	if(!domain)
	{
		return;
	}

	assert(domain->magic == TG_DOMAIN_MAGIC);
	
	tg_jsonfile_free(domain->pattern);
	tg_jsonfile_free(domain->attribute);
	tg_jsonfile_free(domain->pattern_patch);
	tg_jsonfile_free(domain->attribute_patch);

	domain->pattern = NULL;
	domain->attribute = NULL;
	domain->pattern_patch = NULL;
	domain->attribute_patch = NULL;

	if(domain->token_seperators)
	{
		free(domain->token_seperators);
		domain->token_seperator_len = 0;
	}

	tg_hashtable_free(domain->patterns);

	domain->magic = 0;

	free(domain);
}
