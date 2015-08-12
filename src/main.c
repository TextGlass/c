#include "textglass.h"
#include "list.h"

#include <unistd.h>

static int tg_test_file(tg_domain *domain, tg_jsonfile *test_file);
static void tg_printHelp();

int main(int argc, char **argv)
{
	tg_list *tests;
	tg_list_item *item;
	char *pattern = NULL;
	char *attribute = NULL;
	char *pattern_patch = NULL;
	char *attribute_patch = NULL;
	char *test_string = NULL;
	tg_jsonfile *test_file;
	tg_domain *domain = NULL;
	int c, exit = 0;
	struct timespec start, end, diff;

	tg_printd(0, "TextGlass C Client %s\n", TEXTGLASS_VERSION);

	tests = tg_list_init(3);

	//PARSE THE COMMAND LINE

	opterr = 0;

	while ((c = getopt(argc, argv, "p:a:s:b:t:hu:qvw")) != -1)
	{
		switch (c)
		{
			case 'h':
				tg_printHelp();
				goto mdone;
			case 'p':
				pattern = optarg;
				break;
			case 'a':
				attribute = optarg;
				break;
			case 's':
				pattern_patch = optarg;
				break;
			case 'b':
				attribute_patch = optarg;
				break;
			case 't':
				tg_list_add(tests, optarg);
				break;
			case 'u':
				test_string = optarg;
				break;
			case 'q':
				tg_printd_debug_level = 0;
				break;
			case 'v':
				tg_printd_debug_level = 2;
				break;
			case 'w':
				tg_printd_debug_level = 3;
				break;
			default:
				tg_printHelp();
				fprintf(stderr, "\nunknown option: %c\n", optopt);
				exit = 1;
				goto mdone;
		}
	}

	if(!pattern)
	{
		tg_printHelp();
		fprintf(stderr, "\npattern file required\n");
		exit = 1;
		goto mdone;
	}

	//BUILD THE CLIENT

	clock_gettime(CLOCK_REALTIME, &start);

	domain = tg_domain_load(pattern, attribute, pattern_patch, attribute_patch);

	if(!domain)
	{
		fprintf(stderr, "Could not load domain\n");
		exit = 1;
		goto mdone;
	}

	clock_gettime(CLOCK_REALTIME, &end);
	tg_time_diff(&end, &start, &diff);

	tg_printd(0, "Domain load time: %lds %ldms %ld.%ldus\n",
           diff.tv_sec, diff.tv_nsec/1000000, diff.tv_nsec/1000%1000, diff.tv_nsec%1000);

	//DO THE TESTS

	tg_list_foreach(tests, item)
	{
		tg_printd(1, "Test file: %s\n", (char*)item->value);

		test_file = tg_jsonfile_get((char*)item->value);

		if(!test_file)
		{
			fprintf(stderr, "Error reading test file\n");
			exit = 1;
			goto mdone;
		}

		clock_gettime(CLOCK_REALTIME, &start);

		exit += tg_test_file(domain, test_file);

		clock_gettime(CLOCK_REALTIME, &end);
		tg_time_diff(&end, &start, &diff);

		if(exit)
		{
			fprintf(stderr, "Test file failure\n");
			goto mdone;
		}

		tg_printd(0, "All tests passed\n");
		tg_printd(0, "Test time: %lds %ldms %ld.%ldus\n",
			diff.tv_sec, diff.tv_nsec/1000000, diff.tv_nsec/1000%1000, diff.tv_nsec%1000);

		tg_jsonfile_free(test_file);
	}

	//TEST INPUT

	if(test_string)
	{
		tg_printd(0, "Test string: '%s'\n", test_string);

		clock_gettime(CLOCK_REALTIME, &start);

		tg_classify(domain, test_string);

		clock_gettime(CLOCK_REALTIME, &end);
		tg_time_diff(&end, &start, &diff);

		tg_printd(0, "Test time: %lds %ldms %ld.%ldus\n",
			diff.tv_sec, diff.tv_nsec/1000000, diff.tv_nsec/1000%1000, diff.tv_nsec%1000);
	}

	//CLEANUP
mdone:
	tg_list_free(tests);

	tg_domain_free(domain);

	return exit;
}

static void tg_printHelp()
{
	tg_printd(0, "Usage: textglass_client [OPTIONS]\n");
	tg_printd(0, "  -p <file>            load TextGlass pattern file (REQUIRED)\n");
	tg_printd(0, "  -a <file>            load TextGlass attribute file\n");
	tg_printd(0, "  -q <file>            load TextGlass pattern patch file\n");
	tg_printd(0, "  -b <file>            load TextGlass attribute patch file\n");
	tg_printd(0, "  -t <file>            load TextGlass test file\n");
	tg_printd(0, "  -h                   print help\n");
	tg_printd(0, "  -u <string>          test string\n");
}

static int tg_test_file(tg_domain *domain, tg_jsonfile *test_file)
{
	jsmntok_t *tests, *test;
	const char *input;
	int i;

	if(strcmp(test_file->type, "test" ) ||
		strcmp(test_file->domain, domain->domain) ||
		strcmp(test_file->domain_version, domain->domain_version))
	{
		fprintf(stderr, "Invalid test file\n");
		return 1;
	}

	tests = tg_json_get(test_file, test_file->tokens, "tests");

	if(TG_JSON_IS_ARRAY(tests))
	{
		for(i = 0; i < tests->size; i++)
		{
			test = tg_json_array_get(test_file, tests, i);
			
			input = tg_json_get_str(test_file, test, "input");

			if(input)
			{
				tg_printd(2, "Test input: '%s'\n", input);
				tg_classify(domain, input);
			}
		}
	}

	return 0;
}
