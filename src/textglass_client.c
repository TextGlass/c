#include "textglass.h"

static tg_domain *tg_domain_init(tg_jsonfile *pattern, tg_jsonfile *attribute,
		tg_jsonfile *pattern_patch, tg_jsonfile *attribute_patch);

tg_domain *tg_domain_load(const char *pattern, const char *attribute,
		const char *pattern_patch, const char *attribute_patch)
{
	tg_jsonfile *pattern_file = NULL;
	tg_jsonfile *attribute_file = NULL;
	tg_jsonfile *pattern_patch_file = NULL;
	tg_jsonfile *attribute_patch_file = NULL;
	tg_domain *domain = NULL;

	//PARSE ATTRIBUTE FILE

	tg_printd(1, "Pattern file: %s\n", pattern);
	pattern_file = tg_jsonfile_get(pattern);
	if(!pattern_file || strcmp(pattern_file->type, "pattern"))
	{
		fprintf(stderr, "Invalid pattern file\n");
		goto derror;
	}

	//PARSE ATTRIBUTE FILE

	if(attribute)
	{
		tg_printd(1, "Attribute file: %s\n", attribute);
		attribute_file = tg_jsonfile_get(attribute);
		if(!attribute_file  || strcmp(attribute_file->type, "attribute") ||
			strcmp(attribute_file->domain, pattern_file->domain) ||
			strcmp(attribute_file->domain_version, pattern_file->domain_version))
		{
			fprintf(stderr, "Invalid attribute file\n");
			goto derror;
		}
	}

	//PARSE PATTERN PATCH FILE

	if(pattern_patch)
	{
		tg_printd(1, "Pattern patch file: %s\n", pattern_patch);
		pattern_patch_file = tg_jsonfile_get(pattern_patch);
		if(!pattern_patch_file  || strcmp(pattern_patch_file->type, "patternPatch")  ||
			strcmp(pattern_patch_file->domain, pattern_file->domain) ||
			strcmp(pattern_patch_file->domain_version, pattern_file->domain_version))
		{
			fprintf(stderr, "Invalid pattern patch file\n");
			goto derror;
		}
	}

	//PARSE ATTRIBUTE PATCH FILE

	if(attribute_patch)
	{
		tg_printd(1, "Attribute patch file: %s\n", attribute_patch);
		attribute_patch_file = tg_jsonfile_get(attribute_patch);
		if(!attribute_patch_file  || strcmp(attribute_patch_file->type, "attributePatch" ) ||
			strcmp(attribute_patch_file->domain, pattern_file->domain) ||
			strcmp(attribute_patch_file->domain_version, pattern_file->domain_version))
		{
			fprintf(stderr, "Invalid attribute patch file\n");
			goto derror;
		}
	}

	domain = tg_domain_init(pattern_file, attribute_file, pattern_patch_file, attribute_patch_file);

	return domain;

derror:
	tg_domain_free(domain);

	return NULL;
}

static tg_domain *tg_domain_init(tg_jsonfile *pattern, tg_jsonfile *attribute,
		tg_jsonfile *pattern_patch, tg_jsonfile *attribute_patch)
{
	tg_domain *domain;

	assert(pattern);

	domain = calloc(1, sizeof (tg_domain));

	assert(domain);

	domain->pattern = pattern;
	domain->attribute = attribute;
	domain->pattern_patch = pattern_patch;
	domain->attribute_patch = attribute_patch;

	domain->domain = pattern->domain;
	domain->domain_version = pattern->domain_version;

	if(1 == 0)
	{
		goto derror;
	}

	tg_jsonfile_free_tokens(domain->pattern);
	tg_jsonfile_free_tokens(domain->attribute);
	tg_jsonfile_free_tokens(domain->pattern_patch);
	tg_jsonfile_free_tokens(domain->attribute_patch);

	return domain;

derror:
	tg_domain_free(domain);

	return NULL;
}

void tg_domain_free(tg_domain *domain)
{
	if(!domain)
	{
		return;
	}
	
	tg_jsonfile_free(domain->pattern);
	tg_jsonfile_free(domain->attribute);
	tg_jsonfile_free(domain->pattern_patch);
	tg_jsonfile_free(domain->attribute_patch);

	domain->pattern = NULL;
	domain->attribute = NULL;
	domain->pattern_patch = NULL;
	domain->attribute_patch = NULL;

	free(domain);
}