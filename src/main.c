#include "textglass.h"
#include "list.h"

#include <unistd.h>

static void printHelp()
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

	tests = tg_list_init();

	//PARSE THE COMMAND LINE

	opterr = 0;

	while ((c = getopt(argc, argv, "p:a:s:b:t:hu:qvw")) != -1) {
		switch (c)
		{
			case 'h':
				printHelp();
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
				printHelp();
				fprintf(stderr, "\nunknown option: %c\n", optopt);
				exit = 1;
				goto mdone;
		}
	}

	if(!pattern) {
		printHelp();
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
		tg_jsonfile_free(test_file);
	}

	//TEST INPUT

	if(test_string)
	{
		tg_printd(1, "Test string: '%s'\n", test_string);
	}

	//CLEANUP
mdone:
	tg_list_free(tests);

	tg_domain_free(domain);

	return exit;
}
