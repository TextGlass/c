#include "textglass.h"

tg_list *tg_transformer_compile(jsmntok_t *tokens)
{
	tg_list *list;

	list = tg_list_alloc(0, (TG_FREE)&tg_transformer_free);

	if(TG_JSON_IS_ARRAY(tokens))
	{
		tg_printd(2, "Found transformer: %s\n", tokens->str);

		if(0==1)
		{
			goto terror;
		}
	}
	
	return list;
	
terror:
	tg_list_free(list);
	
	return NULL;
}

void tg_transformer_free(tg_transformer *transformer)
{
	assert(transformer && transformer->magic == TG_TRANSFORMER_MAGIC);

	transformer->magic = 0;

	free(transformer);
}