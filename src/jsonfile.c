#include "textglass.h"

tg_jsonfile *tg_jsonfile_get(char *file)
{
	tg_jsonfile *jsonfile;
	FILE *f;
	size_t bytes;
	jsmn_parser parser;
	jsmntok_t *tokens = NULL, *token;
	char *tbuf;
	int token_count, i;

	jsonfile = malloc(sizeof (tg_jsonfile));

	assert(jsonfile);

	jsonfile->filebuf = NULL;
	jsonfile->filebuf_len = 0;

	f = fopen(file, "r");

	if(!f)
	{
		goto jerror;
	}

	fseek(f, 0L, SEEK_END);
	jsonfile->filebuf_len = ftell(f);
	fseek(f, 0L, SEEK_SET);

	if(!jsonfile->filebuf_len)
	{
		goto jerror;
	}

	tg_printd(3, "Reading %s (%zu bytes)\n", file, jsonfile->filebuf_len);

	jsonfile->filebuf = malloc(jsonfile->filebuf_len);

	assert(jsonfile->filebuf);

	bytes = fread(jsonfile->filebuf, 1, jsonfile->filebuf_len, f);

	if(bytes != jsonfile->filebuf_len)
	{
		goto jerror;
	}

	fclose(f);
	f = NULL;

	jsmn_init(&parser);

	token_count = jsmn_parse(&parser, jsonfile->filebuf, jsonfile->filebuf_len, NULL, 0);

	tg_printd(3, "jsmn_parse token count: %d\n", token_count);

	if(token_count < 1)
	{
		goto jerror;
	}

	tokens = malloc(sizeof (jsmntok_t) * token_count);

	assert(tokens);

	jsmn_init(&parser);

	token_count = jsmn_parse(&parser, jsonfile->filebuf, jsonfile->filebuf_len, tokens, token_count);

	for(i = 0; i < token_count; i++)
	{
		token = &tokens[i];

		tbuf = jsonfile->filebuf + token->start;
		tbuf[token->end - token->start] = '\0';

		if(token->type == 3 || token->type == 0)
		{
			tg_printd(3, "token %d: type=%d children=%d s=%d e=%d value='%s'\n", i,
				token->type, token->size, token->start, token->end, tbuf);
		}
	}

	return jsonfile;

jerror:
	if(f)
	{
		fclose(f);
	}

	tg_jsonfile_free(jsonfile);

	if(tokens)
	{
		free(tokens);
	}

	return NULL;
}

void tg_jsonfile_free(tg_jsonfile *jsonfile)
{
	if(!jsonfile)
	{
		return;
	}
	
	if(jsonfile->filebuf) {
		jsonfile->filebuf_len = 0;
		free(jsonfile->filebuf);
	}
	free(jsonfile);
}
