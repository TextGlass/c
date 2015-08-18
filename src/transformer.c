#include "textglass.h"

static tg_transformer *tg_t_lowercase_alloc(jsmntok_t *token);
char *tg_t_lowercase(tg_list *free_list, tg_transformer *transformer, char *input);

static tg_transformer *tg_t_uppercase_alloc(jsmntok_t *token);
char *tg_t_uppercase(tg_list *free_list, tg_transformer *transformer, char *input);

static tg_transformer *tg_t_replaceall_alloc(jsmntok_t *token);
static tg_transformer *tg_t_replacefirst_alloc(jsmntok_t *token);
char *tg_t_replaceall(tg_list *free_list, tg_transformer *transformer, char *input);

static tg_transformer *tg_t_splitget_alloc(jsmntok_t *token);
char *tg_t_splitget(tg_list *free_list, tg_transformer *transformer, char *input);

static tg_transformer *tg_t_isnumber_alloc(jsmntok_t *token);
char *tg_t_isnumber(tg_list *free_list, tg_transformer *transformer, char *input);

static tg_transformer *tg_t_substring_alloc(jsmntok_t *token);
char *tg_t_substring(tg_list *free_list, tg_transformer *transformer, char *input);

tg_list *tg_transformer_compile(jsmntok_t *tokens)
{
	tg_transformer *transformer;
	tg_list *transformers;
	jsmntok_t *token;

	const char *type;
	long i;

	transformers = tg_list_alloc(0, (TG_FREE)&tg_transformer_free);

	if(TG_JSON_IS_ARRAY(tokens))
	{
		for(i = 1; i < tokens[0].skip; i += tokens[i].skip + 1)
		{
			token = &tokens[i];

			type = tg_json_get_str(token, "type");

			if(!type)
			{
				fprintf(stderr, "Transformer type not found\n");
				goto terror;
			}

			if(!strcmp(type, "LowerCase"))
			{
				transformer = tg_t_lowercase_alloc(token);
			}
			else if(!strcmp(type, "UpperCase"))
			{
				transformer = tg_t_uppercase_alloc(token);
			}
			else if(!strcmp(type, "ReplaceAll"))
			{
				transformer = tg_t_replaceall_alloc(token);
			}
			else if(!strcmp(type, "ReplaceFirst"))
			{
				transformer = tg_t_replacefirst_alloc(token);
			}
			else if(!strcmp(type, "SplitAndGet"))
			{
				transformer = tg_t_splitget_alloc(token);
			}
			else if(!strcmp(type, "IsNumber"))
			{
				transformer = tg_t_isnumber_alloc(token);
			}
			else if(!strcmp(type, "Substring"))
			{
				transformer = tg_t_substring_alloc(token);
			}
			else
			{
				fprintf(stderr, "Transformer not found: %s\n", type);
				goto terror;
			}

			if(!transformer)
			{
				goto terror;
			}

			tg_list_add(transformers, transformer);
		}
	}

	return transformers;

terror:
	tg_list_free(transformers);

	return NULL;
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

static tg_transformer *tg_t_lowercase_alloc(jsmntok_t *token)
{
	tg_transformer *lowercase;
	const char *type;

	type = tg_json_get_str(token, "type");

	assert(type && !strcmp(type, "LowerCase"));

	lowercase = tg_transformer_alloc();

	lowercase->transformer = &tg_t_lowercase;

	tg_printd(5, "Found transformer: %s\n", type);

	return lowercase;
}

char *tg_t_lowercase(tg_list *free_list, tg_transformer *transformer, char *input)
{
	assert(free_list && free_list->magic == TG_LIST_MAGIC);
	assert(transformer && transformer->magic == TG_TRANSFORMER_MAGIC);
	assert(input);

	char *p;

	for(p = input; *p; p++)
	{
		*p = tolower(*p);
	}

	return input;
}

static tg_transformer *tg_t_uppercase_alloc(jsmntok_t *token)
{
	tg_transformer *uppercase;
	const char *type;

	type = tg_json_get_str(token, "type");

	assert(type && !strcmp(type, "UpperCase"));

	uppercase = tg_transformer_alloc();

	uppercase->transformer = &tg_t_uppercase;

	tg_printd(5, "Found transformer: %s\n", type);

	return uppercase;
}

char *tg_t_uppercase(tg_list *free_list, tg_transformer *transformer, char *input)
{
	assert(free_list && free_list->magic == TG_LIST_MAGIC);
	assert(transformer && transformer->magic == TG_TRANSFORMER_MAGIC);
	assert(input);

	char *p;

	for(p = input; *p; p++)
	{
		*p = toupper(*p);
	}

	return input;
}

static tg_transformer *tg_t_replaceall_alloc(jsmntok_t *token)
{
	tg_transformer *replaceall;
	jsmntok_t *parameters;
	const char *type;

	type = tg_json_get_str(token, "type");

	assert(type && !strcmp(type, "ReplaceAll"));

	replaceall = tg_transformer_alloc();

	replaceall->transformer = &tg_t_replaceall;
	replaceall->i1 = 0;

	parameters = tg_json_get(token, "parameters");

	if(TG_JSON_IS_OBJECT(parameters))
	{
		replaceall->s1 = tg_json_get_str(parameters, "find");
		replaceall->s2 = tg_json_get_str(parameters, "replaceWith");
	}

	if(!replaceall->s1 || !replaceall->s2 || !replaceall->s1[0])
	{
		fprintf(stderr, "Invalid ReplaceAll transformer\n");
		tg_transformer_free(replaceall);
		return NULL;
	}

	tg_printd(5, "Found transformer: %s, find: '%s', replaceWith: '%s'\n",
		type, replaceall->s1, replaceall->s2);

	return replaceall;
}

static tg_transformer *tg_t_replacefirst_alloc(jsmntok_t *token)
{
	tg_transformer *replacefirst;
	jsmntok_t *parameters;
	const char *type;

	type = tg_json_get_str(token, "type");

	assert(type && !strcmp(type, "ReplaceFirst"));

	replacefirst = tg_transformer_alloc();

	replacefirst->transformer = &tg_t_replaceall;
	replacefirst->i1 = 1;

	parameters = tg_json_get(token, "parameters");

	if(TG_JSON_IS_OBJECT(parameters))
	{
		replacefirst->s1 = tg_json_get_str(parameters, "find");
		replacefirst->s2 = tg_json_get_str(parameters, "replaceWith");
	}

	if(!replacefirst->s1 || !replacefirst->s2 || !replacefirst->s1[0])
	{
		fprintf(stderr, "Invalid ReplaceFirst transformer\n");
		tg_transformer_free(replacefirst);
		return NULL;
	}

	tg_printd(5, "Found transformer: %s, find: '%s', replaceWith: '%s'\n",
		type, replacefirst->s1, replacefirst->s2);

	return replacefirst;
}

char *tg_t_replaceall(tg_list *free_list, tg_transformer *transformer, char *input)
{
	const char *find, *replace_with;
	char *dest, *dest_new;
	size_t dest_len, dest_pos, dest_new_len;
	size_t input_len, input_pos;
	size_t find_len, replace_with_len;
	long replace_count;
	long first;

	assert(free_list && free_list->magic == TG_LIST_MAGIC);
	assert(transformer && transformer->magic == TG_TRANSFORMER_MAGIC);
	assert(input);

	find = transformer->s1;
	replace_with = transformer->s2;

	assert(find);
	assert(replace_with);

	find_len = strlen(find);
	replace_with_len = strlen(replace_with);
	input_len = strlen(input);
	input_pos = 0;
	dest_pos = 0;
	replace_count = 0;
	first = 0;

	if(transformer->i1)
	{
		first = 1;
	}

	if(find_len >= replace_with_len)
	{
		dest = input;
		dest_len = input_len;
	}
	else
	{
		dest_len = input_len + 1 + ((replace_with_len - find_len) * 10);
		dest = malloc(dest_len);

		assert(dest);

		tg_list_add(free_list, dest);

		dest[0] = '\0';
	}

	for(input_pos = 0; input_pos < input_len; input_pos++)
	{
		if(dest_pos + replace_with_len > dest_len)
		{
			assert(dest != input);

			dest_new_len = dest_len * 2;

			dest_new = malloc(dest_new_len);

			assert(dest_new);

			tg_list_add(free_list, dest_new);

			memcpy(dest_new, dest, dest_len);

			dest = dest_new;

			dest_len = dest_new_len;
		}

		if(!strncmp(&input[input_pos], find, find_len) && (!first || (first && !replace_count)))
		{
			memcpy(&dest[dest_pos], replace_with, replace_with_len);

			dest_pos += replace_with_len;
			input_pos += find_len - 1;

			replace_count++;
		}
		else
		{
			dest[dest_pos++] = input[input_pos];
		}
	}

	dest[dest_pos] = '\0';

	return dest;
}

static tg_transformer *tg_t_splitget_alloc(jsmntok_t *token)
{
	tg_transformer *splitget;
	jsmntok_t *parameters;
	const char *type, *get;

	type = tg_json_get_str(token, "type");

	assert(type && !strcmp(type, "SplitAndGet"));

	splitget = tg_transformer_alloc();

	splitget->transformer = &tg_t_splitget;

	parameters = tg_json_get(token, "parameters");

	if(TG_JSON_IS_OBJECT(parameters))
	{
		splitget->s1 = tg_json_get_str(parameters, "delimiter");
		get = tg_json_get_str(parameters, "get");
	}

	if(!splitget->s1 || !get || !splitget->s1[0])
	{
		fprintf(stderr, "Invalid SplitAndGet transformer\n");
		tg_transformer_free(splitget);
		return NULL;
	}

	splitget->i1 = atol(get);

	if(splitget->i1 < -1)
	{
		fprintf(stderr, "Invalid SplitAndGet transformer\n");
		tg_transformer_free(splitget);
		return NULL;
	}

	tg_printd(5, "Found transformer: %s, delimiter: '%s', get: %d\n",
		type, splitget->s1, splitget->i1);

	return splitget;
}

char *tg_t_splitget(tg_list *free_list, tg_transformer *transformer, char *input)
{
	tg_list *split;
	tg_list_item *item;
	const char **seps;
	char *ret = NULL;
	long get;

	assert(free_list && free_list->magic == TG_LIST_MAGIC);
	assert(transformer && transformer->magic == TG_TRANSFORMER_MAGIC);
	assert(input);

	seps = &transformer->s1;
	get = transformer->i1;

	assert(*seps);
	assert(get >= -1);

	split = tg_list_alloc(10, NULL);

	tg_split(input, strlen(input), seps, 1, split);

	if(get == -1)
	{
		get = split->size - 1;
	}

	TG_LIST_FOREACH(split, item)
	{
		if(!get)
		{
			ret = (char*)item->value;
			break;
		}

		get--;
	}

	tg_list_free(split);

	return ret;
}

static tg_transformer *tg_t_isnumber_alloc(jsmntok_t *token)
{
	tg_transformer *isnumber;
	const char *type;

	type = tg_json_get_str(token, "type");

	assert(type && !strcmp(type, "IsNumber"));

	isnumber = tg_transformer_alloc();

	isnumber->transformer = &tg_t_isnumber;

	tg_printd(5, "Found transformer: %s\n", type);

	return isnumber;
}

char *tg_t_isnumber(tg_list *free_list, tg_transformer *transformer, char *input)
{
	char *end;

	assert(free_list && free_list->magic == TG_LIST_MAGIC);
	assert(transformer && transformer->magic == TG_TRANSFORMER_MAGIC);
	assert(input);

	strtoll(input, &end, 10);

	if(!*input || *end)
	{
		return NULL;
	}

	return input;
}

static tg_transformer *tg_t_substring_alloc(jsmntok_t *token)
{
	tg_transformer *substring;
	jsmntok_t *parameters;
	const char *type;

	type = tg_json_get_str(token, "type");

	assert(type && !strcmp(type, "Substring"));

	substring = tg_transformer_alloc();

	substring->transformer = &tg_t_substring;
	substring->i2 = -1;

	parameters = tg_json_get(token, "parameters");

	if(TG_JSON_IS_OBJECT(parameters))
	{
		substring->s1 = tg_json_get_str(parameters, "start");
		substring->s2 = tg_json_get_str(parameters, "maxLength");
	}

	if(!substring->s1 || !substring->s1[0])
	{
		fprintf(stderr, "Invalid Substring transformer\n");
		tg_transformer_free(substring);
		return NULL;
	}

	substring->i1 = atol(substring->s1);

	if(substring->s2)
	{
		substring->i2 = atol(substring->s2);
	}

	if(substring->i1 < 0 || substring->i2 < -1)
	{
		fprintf(stderr, "Invalid Substring transformer\n");
		tg_transformer_free(substring);
		return NULL;
	}

	tg_printd(5, "Found transformer: %s, start: %d, maxLength: %d\n",
		type, substring->i1, substring->i2);

	return substring;
}

char *tg_t_substring(tg_list *free_list, tg_transformer *transformer, char *input)
{
	assert(free_list && free_list->magic == TG_LIST_MAGIC);
	assert(transformer && transformer->magic == TG_TRANSFORMER_MAGIC);
	assert(input);

	assert(transformer->i1 >= 0);
	assert(transformer->i2 >= -1);

	if(transformer->i1 > strlen(input))
	{
		return NULL;
	}

	input += transformer->i1;

	if(transformer->i2 >= 0 && transformer->i2 < strlen(input))
	{
		input[transformer->i2] = '\0';
	}

	return input;
}