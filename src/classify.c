#include "textglass.h"

static void tg_classify_match(tg_classified *classify, const char *token);
static void tg_classify_free(tg_classified *classify);

void tg_classify(tg_domain *domain, const char *original)
{
	char *input, *ngram, *token;
	tg_transformer *transformer;
	size_t length, token_length;
	tg_classified *classify;
	tg_list *tokens = NULL;
	tg_list_item *item;
	size_t i, j, k, ngram_pos;

	classify = calloc(1, sizeof(tg_classified));

	assert(classify);

	classify->magic = TG_CLASSIFIED_MAGIC;
	classify->domain = domain;
	classify->free_list = tg_list_alloc(15, (TG_FREE)&free);

	input = strdup(original);

	assert(input);
	
	tg_list_add(classify->free_list, input);
	
	length = strlen(input);

	tg_printd(3, "Classify input on %s: '%s':%zu\n", domain->domain, input, length);

	//TRANSFORMERS

	if(domain->input_transformers)
	{
		TG_LIST_FOREACH(domain->input_transformers, item)
		{
			transformer = (tg_transformer*)item->value;

			input = transformer->transformer(classify->free_list, transformer, input);

			if(!input)
			{
				tg_printd(3, "Transformer error\n");
				goto cerror;
			}

			length = strlen(input);

			tg_printd(3, "Transformed: '%s':%zu\n", input, length);
		}
	}

	//TOKEN SEPERATORS

	tokens = tg_list_alloc(15, NULL);

	tg_split(input, length, domain->token_seperators, domain->token_seperator_len, tokens);

	if(tg_printd_debug_level >= 3)
	{
		TG_LIST_FOREACH(tokens, item)
		{
			tg_printd(3, "Classify tokens: '%s'\n", (char*)item->value);
		}
	}

	//NGRAMS AND PATTERN MATCHING

	ngram = malloc(length + 1);

	assert(ngram);

	tg_list_add(classify->free_list, ngram);

	classify->matched_tokens = tg_list_alloc(15, NULL);
	classify->candidates = tg_list_alloc(15, NULL);

	for(i = 0; i < tokens->size; i++)
	{
		for(j = domain->ngram_size; j > 0; j--)
		{
			if(i + j > tokens->size)
			{
				continue;
			}

			ngram_pos = 0;

			for(k = i; k < i + j; k++)
			{
				token = (char*)tg_list_get(tokens, k);

				token_length = strlen(token);

				memcpy(ngram + ngram_pos, token, token_length);

				ngram_pos += token_length;
			}

			ngram[ngram_pos] = '\0';

			tg_printd(3, "Ngram: '%s'\n", ngram);

			tg_classify_match(classify, ngram);
		}
	}

	tg_list_free(tokens);
	tg_classify_free(classify);

	return;

cerror:
	tg_list_free(tokens);
	tg_classify_free(classify);

	return;
}

static void tg_classify_match(tg_classified *classify, const char *token)
{
	tg_list *patterns;
	tg_list_item *item;

	assert(classify && classify->magic == TG_CLASSIFIED_MAGIC);
	assert(classify->domain && classify->domain->magic == TG_DOMAIN_MAGIC);

	patterns = tg_hashtable_get(classify->domain->patterns, token);

	if(patterns)
	{
		TG_LIST_FOREACH(patterns, item)
		{
			tg_printd(3, "Hit: '%s' patternId: %s\n", token,
				 ((tg_pattern*)item->value)->pattern_id);
		}
	}
}

static void tg_classify_free(tg_classified *classify)
{
	assert(classify && classify->magic == TG_CLASSIFIED_MAGIC);

	tg_list_free(classify->free_list);

	if(classify->candidates)
	{
		free(classify->candidates);
	}

	if(classify->matched_tokens)
	{
		free(classify->matched_tokens);
	}

	classify->magic = 0;

	free(classify);
}
