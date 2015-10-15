#include <stdio.h>
#include <stdlib.h>

#include "textglass.h"

#include "vcl.h"
#include "vrt.h"
#include "cache/cache.h"
#include "vcc_if.h"


#define VTG_MAX_NAMES		10

typedef struct
{
	unsigned int		magic;
#define VTG_DCONTAINER_MAGIC	0x90A2ED34

	tg_domain		*domains[VTG_MAX_NAMES];
}
vtg_domain_container;

typedef struct
{
	unsigned int		magic;
#define VTG_RCONTAINER_MAGIC	0xBE3F198A

	tg_result		*results[VTG_MAX_NAMES];
}
vtg_result_container;

void vtg_dcontainer_free(void *data)
{
	vtg_domain_container *container;
	size_t name;

	CAST_OBJ_NOTNULL(container, data, VTG_DCONTAINER_MAGIC);

	for(name = 0; name < VTG_MAX_NAMES; name++)
	{
		if(container->domains[name])
		{
			tg_domain_free(container->domains[name]);

			container->domains[name] = NULL;
		}
	}

	FREE_OBJ(container);
}

int init_function(const struct vrt_ctx *ctx, struct vmod_priv *priv_vcl, enum vcl_event_e e)
{
	vtg_domain_container *dcontainer;

	if (e != VCL_EVENT_LOAD)
	{
		return 0;
	}

	ALLOC_OBJ(dcontainer, VTG_DCONTAINER_MAGIC);
	AN(dcontainer);

	priv_vcl->priv = dcontainer;
	priv_vcl->free = vtg_dcontainer_free;

	return 0;
}

VCL_VOID vmod_init_domain(const struct vrt_ctx *ctx, struct vmod_priv *priv_vcl, VCL_INT name,
		VCL_STRING pattern_json, VCL_STRING attribute_json)
{
	vtg_domain_container *dcontainer;

	CAST_OBJ_NOTNULL(dcontainer, priv_vcl->priv, VTG_DCONTAINER_MAGIC);

	if(name < 0 || name >= VTG_MAX_NAMES)
	{
		return;
	}

	if(!*attribute_json)
	{
		attribute_json = NULL;
	}

	if(dcontainer->domains[name])
	{
		tg_domain_free(dcontainer->domains[name]);
	}

	dcontainer->domains[name] = tg_domain_load(pattern_json, attribute_json, NULL, NULL);
}

void vtg_rcontainer_free(void *data)
{
	vtg_result_container *rcontainer;
	size_t name;

	CAST_OBJ_NOTNULL(rcontainer, data, VTG_RCONTAINER_MAGIC);

	for(name = 0; name < VTG_MAX_NAMES; name++)
	{
		if(rcontainer->results[name])
		{
			tg_result_free(rcontainer->results[name]);

			rcontainer->results[name] = NULL;
		}
	}

	FREE_OBJ(rcontainer);
}

VCL_VOID vmod_classify(const struct vrt_ctx *ctx, struct vmod_priv *priv_vcl, struct vmod_priv *priv_task,
		VCL_INT name, VCL_STRING string)
{
	vtg_domain_container *dcontainer;
	vtg_result_container *rcontainer;
	tg_result *result;

	CAST_OBJ_NOTNULL(dcontainer, priv_vcl->priv, VTG_DCONTAINER_MAGIC);

	if(name < 0 || name >= VTG_MAX_NAMES || !string)
	{
		return;
	}

	if(dcontainer->domains[name])
	{
		result = tg_classify(dcontainer->domains[name], string);

		if(result->error_code)
		{
			return;
		}

		CAST_OBJ(rcontainer, priv_task->priv, VTG_RCONTAINER_MAGIC);

		if(!rcontainer)
		{
			ALLOC_OBJ(rcontainer, VTG_RCONTAINER_MAGIC);
			AN(rcontainer);

			priv_task->priv = rcontainer;
			priv_task->free = vtg_rcontainer_free;
		}

		if(rcontainer->results[name])
		{
			tg_result_free(rcontainer->results[name]);
		}

		rcontainer->results[name] = result;
	}
}

VCL_STRING vmod_get_attribute(const struct vrt_ctx *ctx, struct vmod_priv *priv_task,
		VCL_INT name, VCL_STRING attribute)
{
	vtg_result_container *rcontainer;

	if(name < 0 || name >= VTG_MAX_NAMES || !attribute)
	{
		return NULL;
	}

	CAST_OBJ(rcontainer, priv_task->priv, VTG_RCONTAINER_MAGIC);

	if(!rcontainer || !rcontainer->results[name])
	{
		return NULL;
	}

	return tg_result_get(rcontainer->results[name], attribute);
}

VCL_STRING vmod_get_version(const struct vrt_ctx *ctx)
{
	return TEXTGLASS_VERSION;
}
