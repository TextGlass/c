#include "textglass.h"

static void tg_classify_match(tg_classified *classify, const char *token);
static void tg_classify_free(tg_classified *classify);

static tg_result *tg_result_alloc(tg_attribute *attributes, const char *input);
static tg_classified *tg_classified_alloc(const tg_domain *domain);

tg_result *tg_classify(const tg_domain *domain, const char *original)
{
	tg_transformer *transformer;
	tg_classified *classify;
	tg_list *tokens = NULL;
	tg_list_item *item;
	tg_pattern *winner = NULL, *candidate;
	tg_result *result;
	char *input, *ngram, *token;
	size_t length, token_length;
	size_t i, j, k, ngram_pos;
	int rank, wrank;

	classify = tg_classified_alloc(domain);

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

	i = 0;

	TG_LIST_FOREACH(tokens, item)
	{
		for(j = domain->ngram_size; j > 0; j--)
		{
			if(i + j > tokens->size)
			{
				continue;
			}

			ngram_pos = 0;

			for(k = 0; k < j; k++)
			{
				token = (char*)tg_list_get_from(item, k);

				token_length = strlen(token);

				memcpy(ngram + ngram_pos, token, token_length);

				ngram_pos += token_length;
			}

			ngram[ngram_pos] = '\0';

			tg_printd(3, "Ngram: '%s'\n", ngram);

			tg_classify_match(classify, ngram);
		}

		i++;
	}

	//FIND THE WINNER

	TG_LIST_FOREACH(classify->candidates, item)
	{
		candidate = (tg_pattern*)item->value;
		assert(candidate && candidate->magic == TG_PATTERN_MAGIC);

		rank = tg_pattern_rank(candidate);
		wrank = tg_pattern_rank(winner);

		if((wrank > rank || winner == candidate))
		{
			continue;
		}
		
		i = tg_pattern_matched_length(candidate, classify->matched_tokens);

		if(!i)
		{
			continue;
		}

		tg_printd(3, "Candidate: %s, rank=%d, matched=%zu\n", candidate->pattern_id, rank, i);

		if(!winner || rank > wrank || (rank == wrank &&
			i > tg_pattern_matched_length(winner, classify->matched_tokens)))
		{
			winner = candidate;
		}
	}

	tg_printd(3, "Winner: %s\n", winner ? winner->pattern_id : NULL);

	tg_list_free(tokens);
	tg_classify_free(classify);

	if(winner)
	{
		result = tg_result_alloc(winner->attribute, original);
	}
	else
	{
		result = tg_result_alloc(domain->default_attributes, original);

		if(!domain->default_attributes)
		{
			result->pattern_id = domain->default_id;
		}
	}

	return result;

cerror:
	tg_list_free(tokens);
	tg_classify_free(classify);

	result = tg_result_alloc(NULL, original);
	result->error_code = 1;

	return result;
}

static void tg_classify_match(tg_classified *classify, const char *token)
{
	tg_list *patterns;
	tg_list_item *item;
	tg_pattern *candidate;
	char *matched;

	assert(classify && classify->magic == TG_CLASSIFIED_MAGIC);
	assert(classify->domain && classify->domain->magic == TG_DOMAIN_MAGIC);

	patterns = tg_hashtable_get(classify->domain->patterns, token);

	if(patterns)
	{
		matched = strdup(token);

		tg_list_add(classify->free_list, matched);
		
		tg_list_add(classify->matched_tokens, matched);

		TG_LIST_FOREACH(patterns, item)
		{
			candidate = (tg_pattern*)item->value;

			assert(candidate && candidate->magic == TG_PATTERN_MAGIC);

			tg_list_add(classify->candidates, candidate);

			tg_printd(3, "Hit: '%s' patternId: %s\n", matched,
				 candidate->pattern_id);
		}
	}

	return;
}

static tg_result *tg_result_alloc(tg_attribute *attributes, const char *input)
{
	tg_result *result;
	size_t key_len = 0, pos, default_value_pos;
	tg_list *attribute_transformer;
	tg_transformer *transformer;
	char *transformed;
	tg_list_item *item, *item2;

	if(attributes)
	{
		assert(attributes->magic == TG_ATTRIBUTE_MAGIC);
		assert(attributes->key_len == attributes->value_len + attributes->transformers->size);
		key_len = attributes->key_len;
	}

	assert(input);

	result = calloc(1, sizeof(tg_result) + (sizeof(char*) * key_len * 2));

	assert(result);

	result->magic = TG_RESULT_MAGIC;
	result->key_len = key_len;
	result->keys = result->buf;
	result->values = &result->buf[result->key_len];

	if(attributes)
	{
		result->pattern_id = attributes->pattern_id;

		memcpy(result->keys, attributes->keys, attributes->key_len * sizeof(char*));
		memcpy(result->values, attributes->values, attributes->value_len * sizeof(char*));
	}

	if(attributes && attributes->transformers)
	{
		assert(attributes->transformers->magic == TG_LIST_MAGIC);

		if(attributes->transformers->size)
		{
			result->free_list = tg_list_alloc(attributes->transformers->size * 3, (TG_FREE)free);
		}

		pos = attributes->value_len;
		default_value_pos = 0;

		TG_LIST_FOREACH(attributes->transformers, item)
		{
			attribute_transformer = item->value;

			assert(attribute_transformer && attribute_transformer->magic == TG_LIST_MAGIC);

			tg_printd(4, "Transforming: '%s'\n", input);
			
			transformed = strdup(input);

			assert(transformed);

			tg_list_add(result->free_list, transformed);

			TG_LIST_FOREACH(attribute_transformer, item2)
			{
				transformer = (tg_transformer*)item2->value;

				transformed = transformer->transformer(result->free_list, transformer, transformed);

				if(!transformed)
				{
					tg_printd(4, "Transformer error\n");
					transformed = (char*)attributes->default_values[default_value_pos];
					break;
				}

				tg_printd(4, "Transformed: '%s'\n", transformed);
			}

			result->values[pos++] = transformed;

			default_value_pos++;
		}
	}

	return result;
}

void tg_result_free(tg_result *result)
{
	assert(result && result->magic == TG_RESULT_MAGIC);

	result->magic = 0;

	if(result->free_list)
	{
		tg_list_free(result->free_list);
	}

	free(result);
}

static tg_classified *tg_classified_alloc(const tg_domain *domain)
{
	tg_classified *classified;

	classified = calloc(1, sizeof(tg_classified));

	assert(classified);

	classified->magic = TG_CLASSIFIED_MAGIC;
	classified->domain = domain;
	classified->free_list = tg_list_alloc(15, (TG_FREE)&free);

	return classified;
}

static void tg_classify_free(tg_classified *classify)
{
	assert(classify && classify->magic == TG_CLASSIFIED_MAGIC);

	tg_list_free(classify->free_list);

	if(classify->candidates)
	{
		tg_list_free(classify->candidates);
	}

	if(classify->matched_tokens)
	{
		tg_list_free(classify->matched_tokens);
	}

	classify->magic = 0;

	free(classify);
}
