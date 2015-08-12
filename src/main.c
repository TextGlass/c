#include "textglass.h"
#include "list.h"

#include <unistd.h>

static void printHelp()
{
	printf("Usage: textglass_client [OPTIONS]\n");
	printf("  -p <file>            load TextGlass pattern file (REQUIRED)\n");
	printf("  -a <file>            load TextGlass attribute file\n");
	printf("  -q <file>            load TextGlass pattern patch file\n");
	printf("  -b <file>            load TextGlass attribute patch file\n");
	printf("  -t <file>            load TextGlass test file\n");
	printf("  -h                   print help\n");
	printf("  -u <string>          test string\n");
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
	tg_jsonfile *pattern_file = NULL;
	tg_jsonfile *attribute_file = NULL;
	tg_jsonfile *pattern_patch_file = NULL;
	tg_jsonfile *attribute_patch_file = NULL;
	tg_jsonfile *test_file;
	int c, exit = 0;

	printf("TextGlass C Client %s\n", TEXTGLASS_VERSION);

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

	//PARSE PATTERN FILE

	tg_printd(1, "Pattern file: %s\n", pattern);
	pattern_file = tg_jsonfile_get(pattern);
	if(!pattern_file)
	{
		fprintf(stderr, "Error reading pattern file\n");
		exit = 1;
		goto mdone;
	}

	//PARSE ATTRIBUTE FILE

	if(attribute)
	{
		tg_printd(1, "Attribute file: %s\n", attribute);
		attribute_file = tg_jsonfile_get(attribute);
		if(!attribute_file)
		{
			fprintf(stderr, "Error reading attribute file\n");
			exit = 1;
			goto mdone;
		}
	}

	//PARSE PATTERN PATCH FILE

	if(pattern_patch)
	{
		tg_printd(1, "Pattern patch file: %s\n", pattern_patch);
		pattern_patch_file = tg_jsonfile_get(pattern_patch);
		if(!pattern_patch_file)
		{
			fprintf(stderr, "Error reading pattern patch file\n");
			exit = 1;
			goto mdone;
		}
	}

	//PARSE ATTRIBUTE PATCH FILE

	if(attribute_patch)
	{
		tg_printd(1, "Attribute patch file: %s\n", attribute_patch);
		attribute_patch_file = tg_jsonfile_get(attribute_patch);
		if(!attribute_patch_file)
		{
			fprintf(stderr, "Error reading attribute patch file\n");
			exit = 1;
			goto mdone;
		}
	}

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

	tg_jsonfile_free(pattern_file);
	tg_jsonfile_free(attribute_file);
	tg_jsonfile_free(pattern_patch_file);
	tg_jsonfile_free(attribute_patch_file);

	return exit;
}
