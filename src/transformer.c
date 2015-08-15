#include "textglass.h"

static tg_transformer *tg_t_lowercase_alloc(tg_list *transformers);
char *tg_t_lowercase(tg_classified *classify, char *input);
static tg_transformer *tg_transformer_alloc();

tg_list *tg_transformer_compile(jsmntok_t *tokens)
{
	tg_list *transformers;
	jsmntok_t *token;
	tg_transformer *transformer;

	const char *type;
	int i;

	transformers = tg_list_alloc(0, (TG_FREE)&tg_transformer_free);

	if(TG_JSON_IS_ARRAY(tokens))
	{
		for(i = 1; i < tokens[0].skip; i++)
		{
			token = &tokens[i];

			type = tg_json_get_str(token, "type");

			if(!type)
			{
				fprintf(stderr, "Transformer type not found\n");
				goto terror;
			}

			tg_printd(2, "Found transformer: %s\n", type);

			if(!strcmp(type, "LowerCase"))
			{
				transformer = tg_t_lowercase_alloc(transformers);

				if(!transformer)
				{
					goto terror;
				}
			}
			else
			{
				fprintf(stderr, "Transformer not found: %s\n", type);
				goto terror;
			}

			i+= tokens[i].skip;
		}
	}
	
	return transformers;
	
terror:
	tg_list_free(transformers);
	
	return NULL;
}

static tg_transformer *tg_t_lowercase_alloc(tg_list *transformers)
{
	tg_transformer *lowercase;
	
	assert(transformers && transformers->magic == TG_LIST_MAGIC);

	lowercase = tg_transformer_alloc();

	tg_list_add(transformers, lowercase);

	lowercase->transformer = &tg_t_lowercase;

	return lowercase;
}

char *tg_t_lowercase(tg_classified *classify, char *input)
{
	assert(classify && classify->magic == TG_CLASSIFIED_MAGIC);
	assert(input);

	char *p;

	for(p = input ; *p; p++)
	{
		*p = tolower(*p);
	}

	return input;
}

static tg_transformer *tg_transformer_alloc()
{
	tg_transformer *transformer;

	transformer = calloc(1, sizeof(tg_transformer));

	assert(transformer);

	transformer->magic = TG_TRANSFORMER_MAGIC;

	return transformer;
}

void tg_transformer_free(tg_transformer *transformer)
{
	assert(transformer && transformer->magic == TG_TRANSFORMER_MAGIC);

	transformer->magic = 0;

	free(transformer);
}