#include "textglass.h"

tg_jsonfile *tg_jsonfile_get(const char *file)
{
	tg_jsonfile *jsonfile;
	FILE *f;
	size_t bytes;
	jsmn_parser parser;
	jsmntok_t *token, *parent;
	char *tbuf;
	int i;

	assert(file);

	jsonfile = calloc(1, sizeof (tg_jsonfile));

	assert(jsonfile);

	f = fopen(file, "r");

	if(!f)
	{
		fprintf(stderr, "Invalid JSON file\n");
		goto jerror;
	}

	fseek(f, 0L, SEEK_END);
	jsonfile->json_len = ftell(f);
	fseek(f, 0L, SEEK_SET);

	if(!jsonfile->json_len || jsonfile->json_len > 1800 * 1024 * 1024)
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

	jsonfile->tokens = malloc(sizeof (jsmntok_t) * jsonfile->token_len);

	assert(jsonfile->tokens);

	jsmn_init(&parser);

	jsonfile->token_len = jsmn_parse(&parser, jsonfile->json, jsonfile->json_len, jsonfile->tokens, jsonfile->token_len);

	if(jsonfile->token_len < 1 || jsonfile->tokens[0].type != JSMN_OBJECT)
	{
		fprintf(stderr, "Invalid JSON file\n");
		goto jerror;
	}

	for(i = 0; i < jsonfile->token_len; i++)
	{
		token = &jsonfile->tokens[i];

		tbuf = jsonfile->json + token->start;
		tbuf[token->end - token->start] = '\0';

		parent = token;

		while(parent->parent >= 0) {
			parent = &jsonfile->tokens[parent->parent];
			parent->skip++;
		}
	}

	token = tg_json_get(jsonfile, jsonfile->tokens, "TextGlassSpecVersion");

	if(strcmp(TG_JSON_STR(jsonfile, token), "1.0"))
	{
		fprintf(stderr, "Invalid TextGlassSpecVersion: %s\n", TG_JSON_STR(jsonfile, token));
		goto jerror;
	}

	jsonfile->type = TG_JSON_GET_STR(jsonfile, jsonfile->tokens, "type");
	jsonfile->domain = TG_JSON_GET_STR(jsonfile, jsonfile->tokens, "domain");
	jsonfile->domain_version = TG_JSON_GET_STR(jsonfile, jsonfile->tokens, "domainVersion");

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
	
	if(jsonfile->json)
	{
		free(jsonfile->json);
		jsonfile->json_len = 0;
		jsonfile->json = NULL;
	}

	tg_jsonfile_free_tokens(jsonfile);

	free(jsonfile);
}

void tg_jsonfile_free_tokens(tg_jsonfile *jsonfile)
{
	if(!jsonfile)
	{
		return;
	}
	
	if(jsonfile->tokens)
	{
		free(jsonfile->tokens);
		jsonfile->token_len = 0;
		jsonfile->tokens = NULL;
	}
}

jsmntok_t *tg_json_get(tg_jsonfile *jsonfile, jsmntok_t *tokens, const char *field)
{
	int i;

	if(!tokens)
	{
		return NULL;
	}

	assert(tokens[0].type == JSMN_OBJECT);

	for(i = 1; i < tokens[0].skip; i++)
	{
		if(tokens[i].type == JSMN_STRING && !strcmp(jsonfile->json + tokens[i].start, field) &&
			tokens[i].size == 1)
		{
			return &tokens[i + 1];
		}

		i+= tokens[i].skip;
	}

	return NULL;
}
