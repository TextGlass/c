#include "textglass.h"

tg_jsonfile *tg_jsonfile_get(char *file)
{
	tg_jsonfile *jsonfile;
	FILE *f;
	size_t bytes;

	jsonfile = malloc(sizeof (tg_jsonfile));

	assert(jsonfile);

	jsonfile->filebuf = NULL;
	jsonfile->filebuf_len = 0;

	f = fopen(file, "r");

	if(!f)
	{
		goto jerror;
	}

	fseek(f, 0L, SEEK_END);
	jsonfile->filebuf_len = ftell(f);
	fseek(f, 0L, SEEK_SET);

	if(!jsonfile->filebuf_len)
	{
		goto jerror;
	}

	tg_printd(2, "Reading %s (%zu bytes)\n", file, jsonfile->filebuf_len);

	jsonfile->filebuf = malloc(jsonfile->filebuf_len);

	assert(jsonfile->filebuf);

	bytes = fread(jsonfile->filebuf, 1, jsonfile->filebuf_len, f);

	if(bytes != jsonfile->filebuf_len)
	{
		goto jerror;
	}

	fclose(f);

	return jsonfile;

jerror:
	if(f)
	{
		fclose(f);
	}

	tg_jsonfile_free(jsonfile);

	return NULL;
}

void tg_jsonfile_free(tg_jsonfile *jsonfile)
{
	if(!jsonfile)
	{
		return;
	}
	
	if(jsonfile->filebuf) {
		jsonfile->filebuf_len = 0;
		free(jsonfile->filebuf);
	}
	free(jsonfile);
}
