#include <stdio.h>
#include <stdlib.h>

#include "textglass.h"

#include "vcl.h"
#include "vrt.h"
#include "cache/cache.h"

#include "vcc_if.h"

int init_function(const struct vrt_ctx *ctx, struct vmod_priv *priv,
		enum vcl_event_e e)
{
	if (e != VCL_EVENT_LOAD)
	{
		return (0);
	}

	return (0);
}

VCL_STRING vmod_get_version(VRT_CTX)
{
	return TEXTGLASS_VERSION;
}
