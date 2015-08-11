#ifndef _TG_HASHTABLE_H_INCLUDED_
#define _TG_HASHTABLE_H_INCLUDED_

#include <pthread.h>

#include "tree.h"

typedef struct tg_hashtable_key
{
	RB_ENTRY(tg_hashtable_key)	entry;

	const char			*key;
	const void			*value;
}
tg_hashtable_key;

typedef RB_HEAD(tg_hashtable_rbtree, tg_hashtable_key) tg_hashtable_rbtree;

typedef struct
{
	tg_hashtable_rbtree		rbtree;

	pthread_rwlock_t		rwlock;

	size_t				size;
}
tg_hashtable_bucket;

typedef struct
{
	tg_hashtable_bucket		*buckets;

	size_t				bucket_len;
}
tg_hashtable;

tg_hashtable *tg_hashtable_init(size_t buckets);
const void *tg_hashtable_get(tg_hashtable *hashtable, const char *key);
void tg_hashtable_set(tg_hashtable *hashtable, const char *key, const void *value);
int tg_hashtable_delete(tg_hashtable *hashtable, const char *key);
void tg_hashtable_free(tg_hashtable *hashtable);

#endif  /* _TG_HASHTABLE_H_INCLUDED_ */