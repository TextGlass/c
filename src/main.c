#include "textglass.h"
#include "list.h"

static void printHelp()
{
	printf("Usage: textglass_client [OPTIONS] [STRING]\n");
	printf("  -p <file>            load TextGlass pattern file (REQUIRED)\n");
	printf("  -a <file>            load TextGlass attribute file\n");
	printf("  -pp <file>           load TextGlass pattern patch file\n");
	printf("  -ap <file>           load TextGlass attribute patch file\n");
	printf("  -t <file>            load TextGlass test file\n");
	printf("  -h                   print help\n");
	printf("  STRING               test string\n");
}

static char *getParam(int argc, char **args, int pos)
{
	if(pos >= argc) {
		return NULL;
	} else if(args[pos][0] == '-' || !args[pos][0]) {
		return NULL;
	} else {
		return args[pos];
	}
}

int main(int argc, char **args)
{
	tg_list *tests;
	char *pattern = NULL;
	//char *attribute = NULL;
	//char *patternPatch = NULL;
	//char *attributePatch = NULL;
	//char *testString = NULL;
	int i, exit = 0;

	printf("TextGlass C Client %s\n", TEXTGLASS_VERSION);

	tests = tg_list_init();

	//PARSE THE COMMAND LINE

	for(i = 1; i < argc; i++) {
		if(!strcmp(args[i], "-h")) {
			printHelp();
			goto mdone;
		} else if(!strcmp(args[i], "-p")) {
			if(pattern) {
				fprintf(stderr, "pattern file already defined\n");
				exit = 1;
				goto mdone;
			}
			if(!(pattern = getParam(argc, args, ++i)))
			{
				fprintf(stderr, "-p parameter missing\n");
				exit = 1;
				goto mdone;
			}
		} else {
			printHelp();
			fprintf(stderr, "\nunknown option: %s\n", args[i]);
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

mdone:
	tg_list_free(tests);

	return exit;
}
