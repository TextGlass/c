#include "textglass.h"

void tg_classify_free(tg_classified *classify);

void tg_classify(tg_domain *domain, const char *original)
{
	char *input;
	tg_transformer *transformer;
	size_t length;
	tg_classified *classify;
	tg_list *tokens = NULL;
	tg_list *patterns;
	tg_list_item *item, *item_j;

	classify = calloc(1, sizeof(tg_classified));

	assert(classify);

	classify->magic = TG_CLASSIFIED_MAGIC;
	classify->domain = domain;
	classify->free_list = tg_list_alloc(15, (TG_FREE)&free);

	input = strdup(original);
	tg_list_add(classify->free_list, input);
	
	length = strlen(input);

	tg_printd(2, "Classify input on %s: '%s':%zu\n", domain->domain, input, length);

	//TRANSFORMERS

	if(domain->input_transformers)
	{
		tg_list_foreach(domain->input_transformers, item)
		{
			transformer = (tg_transformer*)item->value;

			input = transformer->transformer(classify, input);

			tg_printd(2, "Transformed: '%s'\n", input);
		}
	}

	//TOKEN SEPERATORS

	tokens = tg_list_alloc(15, NULL);

	tg_split(input, length, domain->token_seperators, domain->token_seperator_len, tokens);

	tg_list_foreach(tokens, item)
	{
		tg_printd(3, "Classify tokens: '%s'\n", (char*)item->value);
	}

	//PATTERN MATCHING

	classify->matched_tokens = tg_list_alloc(15, NULL);
	classify->candidates = tg_list_alloc(15, NULL);

	tg_list_foreach(tokens, item)
	{
		patterns = tg_hashtable_get(domain->patterns, (char*)item->value);

		if(patterns)
		{
			tg_list_foreach(patterns, item_j)
			{
				tg_printd(3, "Hit: '%s' patternId: %s\n", (char*)item->value,
					 ((tg_pattern*)item_j->value)->pattern_id);
			}
		}
	}


	tg_list_free(tokens);
	tg_classify_free(classify);

	return;
}

void tg_classify_free(tg_classified *classify)
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
