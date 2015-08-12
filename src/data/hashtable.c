#include "hashtable.h"

static int tg_hashtable_cmp(const tg_hashtable_key *k1, const tg_hashtable_key *k2);

RB_GENERATE(tg_hashtable_rbtree, tg_hashtable_key, entry, tg_hashtable_cmp);

tg_hashtable *tg_hashtable_init(size_t buckets)
{
	tg_hashtable *hashtable;
	tg_hashtable_bucket *bucket;
	size_t i;

	assert(buckets > 0);

	hashtable = malloc(sizeof (tg_hashtable));

	assert(hashtable);

	hashtable->bucket_len = buckets;

	hashtable->buckets = malloc(hashtable->bucket_len * sizeof (tg_hashtable_bucket));

	assert(hashtable->buckets);

	for (i = 0; i < hashtable->bucket_len; i++)
	{
		bucket = &(hashtable->buckets[i]);

		RB_INIT(&bucket->rbtree);

		bucket->size = 0;

		assert(!pthread_rwlock_init(&bucket->rwlock, NULL));
	}

	return hashtable;
}

static tg_hashtable_bucket *tg_hashtable_hash_djb2(const tg_hashtable *hashtable, const char *str)
{
	unsigned long hash = 5381;
	int c;

	assert(hashtable->bucket_len);

	while ((c = *str++))
	{
		hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
	}

	return &(hashtable->buckets[hash % hashtable->bucket_len]);
}

static int tg_hashtable_cmp(const tg_hashtable_key *k1, const tg_hashtable_key *k2)
{
	return strcmp(k1->key, k2->key);
}

const void *tg_hashtable_get(tg_hashtable *hashtable, const char *key)
{
	tg_hashtable_bucket *bucket;
	tg_hashtable_key *result, find;
	const void *ret = NULL;

	assert(hashtable);
	assert(key);

	find.key = key;

	bucket = tg_hashtable_hash_djb2(hashtable, key);

	assert(!pthread_rwlock_rdlock(&bucket->rwlock));

	result = RB_FIND(tg_hashtable_rbtree, &bucket->rbtree, &find);

	if(result)
	{
		ret = result->value;
	}

	assert(!pthread_rwlock_unlock(&bucket->rwlock));

	return ret;
}

void tg_hashtable_set(tg_hashtable *hashtable, const char *key, const void *value)
{
	tg_hashtable_bucket *bucket;
	tg_hashtable_key *add, *ret;

	assert(hashtable);
	assert(key);
	assert(value);

	bucket = tg_hashtable_hash_djb2(hashtable, key);

	assert(!pthread_rwlock_wrlock(&bucket->rwlock));

	add = malloc(sizeof (tg_hashtable_key));

	assert(add);

	add->key = key;
	add->value = value;

	ret = RB_INSERT(tg_hashtable_rbtree, &bucket->rbtree, add);

	if (ret)
	{
		ret->key = key;
		ret->value = value;
	}

	bucket->size++;

	assert(!pthread_rwlock_unlock(&bucket->rwlock));
}

int tg_hashtable_delete(tg_hashtable *hashtable, const char *key)
{
	tg_hashtable_bucket *bucket;
	tg_hashtable_key *result, find;
	int ret = 0;

	assert(hashtable);
	assert(key);

	find.key = key;

	bucket = tg_hashtable_hash_djb2(hashtable, key);

	assert(!pthread_rwlock_wrlock(&bucket->rwlock));

	result = RB_FIND(tg_hashtable_rbtree, &bucket->rbtree, &find);

	if (result)
	{
		RB_REMOVE(tg_hashtable_rbtree, &bucket->rbtree, result);
		free(result);
		bucket->size--;
		ret = 1;
	}

	assert(!pthread_rwlock_unlock(&bucket->rwlock));

	return ret;
}

void tg_hashtable_free(tg_hashtable *hashtable)
{
	tg_hashtable_bucket *bucket;
	tg_hashtable_key *key, *next;
	size_t i;

	assert(hashtable);

	for (i = 0; i < hashtable->bucket_len; i++)
	{
		bucket = &(hashtable->buckets[i]);

		assert(!pthread_rwlock_wrlock(&bucket->rwlock));

		RB_FOREACH_SAFE(key, tg_hashtable_rbtree, &bucket->rbtree, next)
		{
			RB_REMOVE(tg_hashtable_rbtree, &bucket->rbtree, key);
			free(key);
			bucket->size--;
		}

		assert(!bucket->size);

		RB_INIT(&bucket->rbtree);

		assert(!pthread_rwlock_unlock(&bucket->rwlock));

		assert(!pthread_rwlock_destroy(&bucket->rwlock));
	}

	if (hashtable->buckets)
	{
		free(hashtable->buckets);
		hashtable->bucket_len = 0;
		hashtable->buckets = NULL;
	}

	free(hashtable);
}
