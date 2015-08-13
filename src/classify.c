#include "textglass.h"

void tg_classify(tg_domain *domain, const char *original)
{
	char *input;
	size_t length;
	tg_list *tokens;
	tg_list_item *item;

	input = strdup(original);
	length = strlen(input);

	tg_printd(2, "classify input on %s: '%s':%zu\n", domain->domain, input, length);

	//TOKEN SEPERATORS

	tokens = tg_list_init(15, NULL);

	tg_split(input, length, domain->token_seperators, domain->token_seperator_len, tokens);

	tg_list_foreach(tokens, item)
	{
		tg_printd(3, "classify tokens: '%s'\n", (char*)item->value);
	}

	tg_list_free(tokens);
	free(input);
}
