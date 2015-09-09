/*
 * Copyright (c) 2015 TextGlass
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */

#include "textglass.h"

#include <unistd.h>

static int tg_test_file(tg_domain *domain, tg_jsonfile *test_file);
static void tg_printHelp();
static int tg_test_attributes(tg_result *result, jsmntok_t *attributes);

#define TG_MAIN_ERROR(msg) do {fprintf(stderr, "%s", msg); exit = 1; goto mdone; } while(0)

int main(int argc, char **argv)
{
	tg_result *result;
	tg_jsonfile *test_file;
	tg_domain *domain = NULL;
	struct timespec start, end, diff;
	tg_list *tests;
	tg_list_item *item;
	char *pattern = NULL;
	char *attribute = NULL;
	char *pattern_patch = NULL;
	char *attribute_patch = NULL;
	char *test_string = NULL;
	char *option, buf[128];
	int i, exit = 0;
	size_t j;

	tg_printd_debug_level = 1;

	tg_printd(0, "TextGlass C Client %s\n", TEXTGLASS_VERSION);

	tests = tg_list_alloc(3, NULL);

	//PARSE THE COMMAND LINE

	for(i = 1; i < argc; i++)
	{
		option = argv[i];

		if(!strcmp(option, "-h"))
		{
			tg_printHelp();
			return 0;
		}
		else if(!strcmp(option, "-p") && (i + 1) < argc && *argv[i + 1] != '-')
		{
			if(pattern)
			{
				TG_MAIN_ERROR("pattern file already defined\n");
			}
			pattern = argv[++i];
		}
		else if(!strcmp(option, "-a") && (i + 1) < argc && *argv[i + 1] != '-')
		{
			if(attribute)
			{
				TG_MAIN_ERROR("attribute file already defined\n");
			}
			attribute = argv[++i];
		}
		else if(!strcmp(option, "-pp") && (i + 1) < argc && *argv[i + 1] != '-')
		{
			if(pattern_patch)
			{
				TG_MAIN_ERROR("pattern patch file already defined\n");
			}
			pattern_patch = argv[++i];
		}
		else if(!strcmp(option, "-ap") && (i + 1) < argc && *argv[i + 1] != '-')
		{
			if(attribute_patch)
			{
				TG_MAIN_ERROR("attribute patch file already defined\n");
			}
			attribute_patch = argv[++i];
		}
		else if(!strcmp(option, "-t") && (i + 1) < argc && *argv[i + 1] != '-')
		{
			tg_list_add(tests, argv[++i]);
		}
		else if(*option != '-' && !test_string)
		{
			test_string = option;
		}
		else if(!strcmp(option, "-q"))
		{
			tg_printd_debug_level = 0;
		}
		else if(!strcmp(option, "-v"))
		{
			tg_printd_debug_level = 2;
		}
		else if(!strcmp(option, "-vv"))
		{
			tg_printd_debug_level = 5;
		}
		else
		{
			tg_printHelp();
			sprintf(buf, "unknown option: %s\n", option);
			TG_MAIN_ERROR(buf);
		}
	}

	if(!pattern)
	{
		tg_printHelp();
		TG_MAIN_ERROR("\npattern file required\n");
	}

	//BUILD THE CLIENT

	clock_gettime(CLOCK_REALTIME, &start);

	domain = tg_domain_load(pattern, attribute, pattern_patch, attribute_patch);

	clock_gettime(CLOCK_REALTIME, &end);
	tg_time_diff(&end, &start, &diff);

	if(!domain)
	{
		TG_MAIN_ERROR("Could not load domain\n");
	}

	tg_printd(0, "Domain load time: %lds %ldms %ld.%ldus\n",
		diff.tv_sec, diff.tv_nsec / 1000000, diff.tv_nsec / 1000 % 1000, diff.tv_nsec % 1000);

	//DO THE TESTS

	TG_LIST_FOREACH(tests, item)
	{
		tg_printd(1, "Test file: %s\n", (char*)item->value);

		test_file = tg_jsonfile_get((char*)item->value);

		if(!test_file)
		{
			TG_MAIN_ERROR("Error reading test file\n");
		}

		clock_gettime(CLOCK_REALTIME, &start);

		exit += tg_test_file(domain, test_file);

		clock_gettime(CLOCK_REALTIME, &end);
		tg_time_diff(&end, &start, &diff);

		if(exit)
		{
			tg_jsonfile_free(test_file);
			TG_MAIN_ERROR("Test file failure\n");
		}

		tg_printd(0, "All tests passed\n");
		tg_printd(0, "Test time: %lds %ldms %ld.%ldus\n",
			diff.tv_sec, diff.tv_nsec / 1000000, diff.tv_nsec / 1000 % 1000, diff.tv_nsec % 1000);

		tg_jsonfile_free(test_file);
	}

	//TEST INPUT

	if(test_string)
	{
		tg_printd(0, "Test string: '%s'\n", test_string);

		clock_gettime(CLOCK_REALTIME, &start);

		result = tg_classify(domain, test_string);

		clock_gettime(CLOCK_REALTIME, &end);
		tg_time_diff(&end, &start, &diff);

		assert(result);

		if(result->error_code)
		{
			tg_printd(0, "Test error: %d\n", result->error_code);
		}
		else
		{
			tg_printd(0, "Test result: %s\n", result->pattern_id);
		}

		for(j = 0; j < result->key_len; j++)
		{
			tg_printd(1, "Test attribute: '%s'='%s'\n", result->keys[j], result->values[j]);
		}

		tg_result_free(result);

		tg_printd(0, "Test time: %lds %ldms %ld.%ldus\n",
			diff.tv_sec, diff.tv_nsec / 1000000, diff.tv_nsec / 1000 % 1000, diff.tv_nsec % 1000);
	}

mdone:
	//CLEANUP

	tg_list_free(tests);

	tg_domain_free(domain);

	return exit;
}

static void tg_printHelp()
{
	tg_printd(0, "Usage: textglass_client [OPTIONS] [STRING]\n");
	tg_printd(0, "  -p <file>            load TextGlass pattern file (REQUIRED)\n");
	tg_printd(0, "  -a <file>            load TextGlass attribute file\n");
	tg_printd(0, "  -pp <file>           load TextGlass pattern patch file\n");
	tg_printd(0, "  -ap <file>           load TextGlass attribute patch file\n");
	tg_printd(0, "  -t <file>            load TextGlass test file\n");
	tg_printd(0, "  -h                   print help\n");
	tg_printd(0, "  -q                   quiet\n");
	tg_printd(0, "  -v                   verbose\n");
	tg_printd(0, "  -vv                  very verbose\n");
	tg_printd(0, "  STRING               test string\n");
}

static int tg_test_file(tg_domain *domain, tg_jsonfile *test_file)
{
	jsmntok_t *tests, *test, *attributes;
	tg_result *result;
	const char *expected;
	const char *input;
	int errors = 0;
	long i;

	assert(domain && domain->magic == TG_DOMAIN_MAGIC);
	assert(test_file && test_file->magic == TG_JSONFILE_MAGIC);

	if(strcmp(test_file->type, "test") ||
		strcmp(test_file->domain, domain->domain) ||
		strcmp(test_file->domain_version, domain->domain_version))
	{
		fprintf(stderr, "Invalid test file\n");
		return 1;
	}

	tests = tg_json_get(test_file->tokens, "tests");

	if(TG_JSON_IS_ARRAY(tests))
	{
		for(i = 1; i < tests[0].skip; i += tests[i].skip)
		{
			test = &tests[i];

			input = tg_json_get_str(test, "input");
			expected = tg_json_get_str(test, "resultPatternId");

			if(expected && !strcmp(expected, "null") &&
				TG_JSON_IS_LITERAL(tg_json_get(test, "resultPatternId")))
			{
				expected = NULL;
			}

			if(input)
			{
				tg_printd(2, "Test input: '%s'\n", input);

				result = tg_classify(domain, input);

				assert(result);

				if(result->error_code)
				{
					tg_printd(2, "FAILED: error_code=%d\n", result->error_code);
					tg_result_free(result);
					errors++;
					continue;
				}
				else if(!result->pattern_id && !expected)
				{
					tg_printd(2, "PASS: null\n");
					tg_result_free(result);
					continue;
				}
				else if(!result->pattern_id || !expected || strcmp(result->pattern_id, expected))
				{
					tg_printd(2, "FAILED: expected patternId: %s, got: %s\n", expected, result->pattern_id);
					tg_result_free(result);
					errors++;
					continue;
				}

				attributes = tg_json_get(test, "resultAttributes");

				if(tg_test_attributes(result, attributes))
				{
					tg_result_free(result);
					errors++;
					continue;
				}

				tg_printd(2, "PASS: %s\n", result->pattern_id);

				tg_result_free(result);
			}
		}
	}

	return errors;
}

static int tg_test_attributes(tg_result *result, jsmntok_t *attributes)
{
	const char *key, *expected, *value;
	long i;

	assert(result && result->magic == TG_RESULT_MAGIC);

	if(TG_JSON_IS_OBJECT(attributes))
	{
		for(i = 1; i < attributes[0].skip; i += attributes[i].skip)
		{
			key = attributes[i].str;
			expected = attributes[i + 1].str;

			value = tg_result_get(result, key);

			if(!value || strcmp(value, expected))
			{
				tg_printd(2, "FAILED: expected '%s'='%s', got: %s\n", key, expected, value);
				return 1;
			}
		}
	}

	return 0;
}
