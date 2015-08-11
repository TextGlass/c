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
	char *patternPatch = NULL;
	char *attributePatch = NULL;
	char *testString = NULL;
	int c, exit = 0;

	printf("TextGlass C Client %s\n", TEXTGLASS_VERSION);

	tests = tg_list_init();

	//PARSE THE COMMAND LINE

	opterr = 0;

	while ((c = getopt(argc, argv, "p:a:q:b:t:hu:")) != -1) {
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
			case 'q':
				patternPatch = optarg;
				break;
			case 'b':
				attributePatch = optarg;
				break;
			case 't':
				tg_list_add(tests, optarg);
				break;
			case 'u':
				testString = optarg;
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

	printf("Pattern file: %s\n", pattern);

	if(attribute)
	{
		printf("Attribute file: %s\n", attribute);
	}

	if(patternPatch)
	{
		printf("Pattern patch file: %s\n", patternPatch);
	}

	if(attributePatch)
	{
		printf("Attribute patch file: %s\n", attributePatch);
	}

	tg_list_foreach(tests, item)
	{
		printf("Test file: %s\n", (char*)item->value);
	}

	if(testString)
	{
		printf("Test string: '%s'\n", testString);
	}

mdone:
	tg_list_free(tests);

	return exit;
}
