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

tg_jsonfile *tg_jsonfile_get(const char *file)
{
	tg_jsonfile *jsonfile;
	FILE *f;
	size_t bytes;
	jsmn_parser parser;
	jsmntok_t *token, *parent;
	long i;

	assert(file);

	jsonfile = calloc(1, sizeof(tg_jsonfile));

	assert(jsonfile);

	jsonfile->magic = TG_JSONFILE_MAGIC;

	f = fopen(file, "r");

	if(!f)
	{
		fprintf(stderr, "Invalid JSON file\n");
		goto jerror;
	}

	fseek(f, 0L, SEEK_END);
	jsonfile->json_len = ftell(f);
	fseek(f, 0L, SEEK_SET);

	if(!jsonfile->json_len || (sizeof(long) == 4 &&
		jsonfile->json_len > 1800 * 1024 * 1024))
	{
		fprintf(stderr, "Invalid JSON file\n");
		goto jerror;
	}

	tg_printd(2, "Reading %s (%zu bytes)\n", file, jsonfile->json_len);

	jsonfile->json = malloc(jsonfile->json_len);

	assert(jsonfile->json);

	bytes = fread(jsonfile->json, 1, jsonfile->json_len, f);

	if(bytes != jsonfile->json_len)
	{
		fprintf(stderr, "Invalid JSON file\n");
		goto jerror;
	}

	fclose(f);
	f = NULL;

	jsmn_init(&parser);

	jsonfile->token_len = jsmn_parse(&parser, jsonfile->json, jsonfile->json_len, NULL, 0);

	if(jsonfile->token_len < 1)
	{
		fprintf(stderr, "Invalid JSON file\n");
		goto jerror;
	}

	jsonfile->tokens = malloc(sizeof(jsmntok_t) * jsonfile->token_len);

	assert(jsonfile->tokens);

	jsmn_init(&parser);

	jsonfile->token_len = jsmn_parse(&parser, jsonfile->json, jsonfile->json_len, jsonfile->tokens, jsonfile->token_len);

	if(jsonfile->token_len < 1 || !TG_JSON_IS_OBJECT(jsonfile->tokens))
	{
		fprintf(stderr, "Invalid JSON file\n");
		goto jerror;
	}

	for(i = 0; i < jsonfile->token_len; i++)
	{
		token = &jsonfile->tokens[i];

		token->str = jsonfile->json + token->start;
		jsonfile->json[token->end] = '\0';

		token->skip = 1;

		parent = token;

		while(parent->parent >= 0)
		{
			parent = &jsonfile->tokens[parent->parent];
			parent->skip++;
		}
	}

	token = tg_json_get(jsonfile->tokens, "TextGlassSpecVersion");

	if(!token || strcmp(token->str, "1.0"))
	{
		fprintf(stderr, "Invalid TextGlassSpecVersion found\n");
		goto jerror;
	}

	jsonfile->type = tg_json_get_str(jsonfile->tokens, "type");
	jsonfile->domain = tg_json_get_str(jsonfile->tokens, "domain");
	jsonfile->domain_version = tg_json_get_str(jsonfile->tokens, "domainVersion");

	if(!jsonfile->type || !jsonfile->domain || !jsonfile->domain_version)
	{
		fprintf(stderr, "Invalid JSON file\n");
		goto jerror;
	}

	tg_printd(1, "Loaded %s file, domain: %s, version: %s, json tokens: %d\n",
		jsonfile->type, jsonfile->domain, jsonfile->domain_version, jsonfile->token_len);

	return jsonfile;

jerror:
	if(f)
	{
		fclose(f);
	}

	tg_jsonfile_free(jsonfile);

	return NULL;
}

void tg_jsonfile_free(tg_jsonfile *jsonfile)
{
	if(!jsonfile)
	{
		return;
	}

	assert(jsonfile->magic == TG_JSONFILE_MAGIC);

	if(jsonfile->json)
	{
		free(jsonfile->json);
	}

	tg_jsonfile_free_tokens(jsonfile);

	jsonfile->magic = 0;

	free(jsonfile);
}

void tg_jsonfile_free_tokens(tg_jsonfile *jsonfile)
{
	if(!jsonfile)
	{
		return;
	}

	assert(jsonfile->magic == TG_JSONFILE_MAGIC);

	if(jsonfile->tokens)
	{
		free(jsonfile->tokens);
		jsonfile->token_len = 0;
		jsonfile->tokens = NULL;
	}
}

jsmntok_t *tg_json_get(jsmntok_t *tokens, const char *field)
{
	long i;

	assert(field);

	if(!tokens || !TG_JSON_IS_OBJECT(tokens))
	{
		return NULL;
	}

	for(i = 1; i < tokens[0].skip; i += tokens[i].skip)
	{
		if(TG_JSON_IS_STRING(&tokens[i]) && !strcmp(tokens[i].str, field) &&
			tokens[i].size == 1)
		{
			return &tokens[i + 1];
		}
	}

	return NULL;
}

const char *tg_json_get_str(jsmntok_t *tokens, const char *field)
{
	jsmntok_t *token = tg_json_get(tokens, field);

	if(!token)
	{
		return NULL;
	}
	else
	{
		return token->str;
	}
}
