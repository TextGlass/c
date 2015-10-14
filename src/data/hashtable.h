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

#ifndef _TG_HASHTABLE_H_INCLUDED_
#define _TG_HASHTABLE_H_INCLUDED_

#include <stdlib.h>
#include <string.h>

#ifndef _TEXTGLASS_SKIP_ASSERT
#include <assert.h>
#endif

#include "tree.h"


#define TG_HASHTABLE_PREALLOC_LEN	2


typedef struct tg_hashtable_key
{
	unsigned int			magic;
#define	TG_HASHTABLE_KEY_MAGIC		0x4D2FA1FF

	RB_ENTRY(tg_hashtable_key)	entry;

	const char			*key;
	void				*value;

	int				malloc:1;
}
tg_hashtable_key;


typedef RB_HEAD(tg_hashtable_rbtree, tg_hashtable_key) tg_hashtable_rbtree;


typedef struct
{
	unsigned int			magic;
#define	TG_HASHTABLE_BUCKET_MAGIC	0xA11FB208

	tg_hashtable_rbtree		rbtree;

	size_t				size;
	size_t				prealloc_len;

	tg_hashtable_key		prealloc[TG_HASHTABLE_PREALLOC_LEN];
}
tg_hashtable_bucket;


typedef struct
{
	unsigned int			magic;
#define	TG_HASHTABLE_MAGIC		0x815BDDAB

	tg_hashtable_bucket		*buckets;

	size_t				bucket_len;

	void				(*callback)(void*);
}
tg_hashtable;


tg_hashtable *tg_hashtable_alloc(size_t buckets, void (*callback)(void *value));
void *tg_hashtable_get(tg_hashtable *hashtable, const char *key);
void tg_hashtable_set(tg_hashtable *hashtable, const char *key, void *value);
int tg_hashtable_delete(tg_hashtable *hashtable, const char *key);
size_t tg_hashtable_size(tg_hashtable *hashtable);
void tg_hashtable_free(tg_hashtable *hashtable);


#endif  /* _TG_HASHTABLE_H_INCLUDED_ */
