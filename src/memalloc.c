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

void tg_memalloc_init(tg_memalloc *memalloc, void *buf, size_t available)
{
	assert(memalloc);

	memalloc->magic = TG_MEMALLOC_MAGIC;

	memalloc->buf = buf;
	memalloc->available = available;
	memalloc->used = 0;
	memalloc->enabled = 0;
	memalloc->free_list = NULL;

	if(available)
	{
		memalloc->enabled = 1;
	}
}

tg_attributes *tg_memalloc_bootstrap(void *buf, size_t available, size_t keys)
{
	tg_attributes *attributes;
	size_t size;

	assert(buf && available);

	size = tg_attributes_size(keys);

	if(size > available)
	{
		tg_printd(1, "tg_memalloc_bootstrap() out of memory, requested: %zu, available: %zu\n",
			 size, available);

		return NULL;
	}

	attributes = buf;

	tg_attributes_init(attributes, keys);

	tg_memalloc_init(&attributes->memalloc, buf, available);

	attributes->memalloc.used += size;

	assert(attributes->memalloc.available >= attributes->memalloc.used);

	return attributes;
}

void *tg_memalloc_malloc(tg_memalloc *memalloc, size_t size)
{
	void *ret;

	assert(memalloc && memalloc->magic == TG_MEMALLOC_MAGIC);

	if(!memalloc->enabled)
	{
		ret = malloc(size);

		assert(ret);

		return ret;
	}

	if(!size || (size + memalloc->used) > memalloc->available)
	{
		tg_printd(1, "tg_memalloc_malloc() out of memory, requested: %zu, available: %zu-%zu\n",
			 size, memalloc->available, memalloc->used);

		return NULL;
	}

	ret = memalloc->buf + memalloc->used;

	memalloc->used += size;

	return ret;
}

void tg_memalloc_add_free(tg_memalloc *memalloc, void *ptr)
{
	assert(memalloc && memalloc->magic == TG_MEMALLOC_MAGIC);

	if(memalloc->free_list)
	{
		tg_list_add(memalloc->free_list, ptr);
	}
}