#ifndef _TG_HASHTABLE_H_INCLUDED_
#define _TG_HASHTABLE_H_INCLUDED_

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "tree.h"

#define TG_HASHTABLE_PREALLOC_LEN		2

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

	void(*callback)			(void*);
}
tg_hashtable;

tg_hashtable *tg_hashtable_alloc(size_t buckets, void (*free)(void *value));
void *tg_hashtable_get(tg_hashtable *hashtable, const char *key);
void tg_hashtable_set(tg_hashtable *hashtable, const char *key, void *value);
int tg_hashtable_delete(tg_hashtable *hashtable, const char *key);
void tg_hashtable_free(tg_hashtable *hashtable);

#endif  /* _TG_HASHTABLE_H_INCLUDED_ */