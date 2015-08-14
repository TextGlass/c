#include "textglass.h"

void tg_classify(tg_domain *domain, const char *original)
{
	char *input;
	size_t length;
	tg_list *tokens = NULL;
	tg_list *matched_tokens = NULL;
	tg_list *candidates = NULL;
	tg_list *patterns;
	tg_list_item *item, *item_j;

	input = strdup(original);
	length = strlen(input);

	tg_printd(2, "classify input on %s: '%s':%zu\n", domain->domain, input, length);

	//TOKEN SEPERATORS

	tokens = tg_list_alloc(15, NULL);

	tg_split(input, length, domain->token_seperators, domain->token_seperator_len, tokens);

	tg_list_foreach(tokens, item)
	{
		tg_printd(3, "classify tokens: '%s'\n", (char*)item->value);
	}

	//PATTERN MATCHING

	matched_tokens = tg_list_alloc(15, NULL);
	candidates = tg_list_alloc(15, NULL);

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

	tg_list_free(candidates);
	tg_list_free(matched_tokens);
	tg_list_free(tokens);
	
	free(input);
}
