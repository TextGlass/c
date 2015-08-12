#include "textglass.h"

tg_jsonfile *tg_jsonfile_get(char *file)
{
	tg_jsonfile *jsonfile;
	FILE *f;
	size_t bytes;
	jsmn_parser parser;
	jsmntok_t *token, *parent;
	char *tbuf;
	int i;

	jsonfile = malloc(sizeof (tg_jsonfile));

	assert(jsonfile);

	jsonfile->json = NULL;
	jsonfile->json_len = 0;
	jsonfile->tokens = NULL;
	jsonfile->token_len = 0;

	f = fopen(file, "r");

	if(!f)
	{
		goto jerror;
	}

	fseek(f, 0L, SEEK_END);
	jsonfile->json_len = ftell(f);
	fseek(f, 0L, SEEK_SET);

	if(!jsonfile->json_len || jsonfile->json_len > 1800 * 1024 * 1024)
	{
		goto jerror;
	}

	tg_printd(3, "Reading %s (%zu bytes)\n", file, jsonfile->json_len);

	jsonfile->json = malloc(jsonfile->json_len);

	assert(jsonfile->json);

	bytes = fread(jsonfile->json, 1, jsonfile->json_len, f);

	if(bytes != jsonfile->json_len)
	{
		goto jerror;
	}

	fclose(f);
	f = NULL;

	jsmn_init(&parser);

	jsonfile->token_len = jsmn_parse(&parser, jsonfile->json, jsonfile->json_len, NULL, 0);

	tg_printd(3, "jsmn_parse token count: %d\n", jsonfile->token_len);

	if(jsonfile->token_len < 1)
	{
		goto jerror;
	}

	jsonfile->tokens = malloc(sizeof (jsmntok_t) * jsonfile->token_len);

	assert(jsonfile->tokens);

	jsmn_init(&parser);

	jsonfile->token_len = jsmn_parse(&parser, jsonfile->json, jsonfile->json_len, jsonfile->tokens, jsonfile->token_len);

	if(jsonfile->token_len < 1 || jsonfile->tokens[0].type != JSMN_OBJECT)
	{
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
	tg_printd(3, "TextGlassSpecVersion: %s\n", TG_JSON_STR(jsonfile, token));

	token = tg_json_get(jsonfile, jsonfile->tokens, "legal");
	token = tg_json_get(jsonfile, token, "copyright");
	tg_printd(3, "Copyright: %s\n", TG_JSON_STR(jsonfile, token));

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
		jsonfile->json_len = 0;
		free(jsonfile->json);
	}

	if(jsonfile->tokens)
	{
		jsonfile->token_len = 0;
		free(jsonfile->tokens);
	}

	free(jsonfile);
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
