#include "hashtable.h"

static int tg_hashtable_cmp(const tg_hashtable_key *k1, const tg_hashtable_key *k2);

RB_GENERATE(tg_hashtable_rbtree, tg_hashtable_key, entry, tg_hashtable_cmp);

tg_hashtable *tg_hashtable_alloc(size_t buckets, void (*free)(void *value))
{
	tg_hashtable *hashtable;
	tg_hashtable_bucket *bucket;
	size_t i, j;

	assert(buckets > 0);

	hashtable = malloc(sizeof(tg_hashtable));

	assert(hashtable);

	hashtable->magic = TG_HASHTABLE_MAGIC;
	hashtable->bucket_len = buckets;
	hashtable->callback = free;

	hashtable->buckets = malloc(hashtable->bucket_len * sizeof(tg_hashtable_bucket));

	assert(hashtable->buckets);

	for(i = 0; i < hashtable->bucket_len; i++)
	{
		bucket = &(hashtable->buckets[i]);

		bucket->magic = TG_HASHTABLE_BUCKET_MAGIC;
		bucket->prealloc_len = TG_HASHTABLE_PREALLOC_LEN;

		RB_INIT(&bucket->rbtree);

		bucket->size = 0;

		for(j = 0; j < bucket->prealloc_len; j++)
		{
			bucket->prealloc[j].magic = 0;
		}
	}

	return hashtable;
}

static tg_hashtable_bucket *tg_hashtable_hash_djb2(const tg_hashtable *hashtable, const char *str)
{
	unsigned long hash = 5381;
	int c;

	assert(hashtable && hashtable->magic == TG_HASHTABLE_MAGIC);
	assert(hashtable->bucket_len);
	assert(str);

	while((c = *str++))
	{
		hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
	}

	return &(hashtable->buckets[hash % hashtable->bucket_len]);
}

static int tg_hashtable_cmp(const tg_hashtable_key *k1, const tg_hashtable_key *k2)
{
	return strcmp(k1->key, k2->key);
}

static tg_hashtable_key *tg_hashtable_key_alloc(tg_hashtable_bucket *bucket)
{
	tg_hashtable_key *key;
	size_t i;

	assert(bucket && bucket->magic == TG_HASHTABLE_BUCKET_MAGIC);

	for(i = 0; i < bucket->prealloc_len; i++)
	{
		key = &bucket->prealloc[i];

		if(!key->magic)
		{
			key->magic = TG_HASHTABLE_KEY_MAGIC;
			key->malloc = 0;

			return key;
		}
	}

	key = malloc(sizeof(tg_hashtable_key));

	assert(key);

	key->magic = TG_HASHTABLE_KEY_MAGIC;
	key->malloc = 1;

	return key;
}

static void tg_hashtable_key_free(tg_hashtable_key *key)
{
	assert(key && key->magic == TG_HASHTABLE_KEY_MAGIC);

	key->magic = 0;

	if(key->malloc)
	{
		free(key);
	}
}

void *tg_hashtable_get(tg_hashtable *hashtable, const char *key)
{
	tg_hashtable_bucket *bucket;
	tg_hashtable_key *result, find;
	void *ret = NULL;

	assert(hashtable && hashtable->magic == TG_HASHTABLE_MAGIC);
	assert(key);

	find.key = key;

	bucket = tg_hashtable_hash_djb2(hashtable, key);

	assert(bucket->magic == TG_HASHTABLE_BUCKET_MAGIC);

	result = RB_FIND(tg_hashtable_rbtree, &bucket->rbtree, &find);

	if(result)
	{
		assert(result->magic == TG_HASHTABLE_KEY_MAGIC);

		ret = result->value;
	}

	return ret;
}

void tg_hashtable_set(tg_hashtable *hashtable, const char *key, void *value)
{
	tg_hashtable_bucket *bucket;
	tg_hashtable_key *add, *ret;

	assert(hashtable && hashtable->magic == TG_HASHTABLE_MAGIC);
	assert(key);
	assert(value);

	bucket = tg_hashtable_hash_djb2(hashtable, key);

	assert(bucket->magic == TG_HASHTABLE_BUCKET_MAGIC);

	add = tg_hashtable_key_alloc(bucket);

	add->key = key;
	add->value = value;

	ret = RB_INSERT(tg_hashtable_rbtree, &bucket->rbtree, add);

	if(ret)
	{
		if(hashtable->callback)
		{
			hashtable->callback(ret->value);
		}

		tg_hashtable_key_free(add);

		assert(ret->magic == TG_HASHTABLE_KEY_MAGIC);

		ret->key = key;
		ret->value = value;
	}
	else
	{
		bucket->size++;
	}
}

int tg_hashtable_delete(tg_hashtable *hashtable, const char *key)
{
	tg_hashtable_bucket *bucket;
	tg_hashtable_key *result, find;
	int ret = 0;

	assert(hashtable && hashtable->magic == TG_HASHTABLE_MAGIC);
	assert(key);

	find.key = key;

	bucket = tg_hashtable_hash_djb2(hashtable, key);

	assert(bucket->magic == TG_HASHTABLE_BUCKET_MAGIC);

	result = RB_FIND(tg_hashtable_rbtree, &bucket->rbtree, &find);

	if(result)
	{
		assert(result->magic == TG_HASHTABLE_KEY_MAGIC);

		RB_REMOVE(tg_hashtable_rbtree, &bucket->rbtree, result);

		if(hashtable->callback)
		{
			hashtable->callback(result->value);
		}

		tg_hashtable_key_free(result);

		bucket->size--;

		ret = 1;
	}

	return ret;
}

size_t tg_hashtable_size(tg_hashtable *hashtable)
{
	tg_hashtable_bucket *bucket;
	size_t i, size = 0;

	assert(hashtable && hashtable->magic == TG_HASHTABLE_MAGIC);

	for(i = 0; i < hashtable->bucket_len; i++)
	{
		bucket = &hashtable->buckets[i];

		assert(bucket->magic == TG_HASHTABLE_BUCKET_MAGIC);

		size += bucket->size;
	}

	return size;
}

void tg_hashtable_free(tg_hashtable *hashtable)
{
	tg_hashtable_bucket *bucket;
	tg_hashtable_key *key, *next;
	size_t i;

	assert(hashtable && hashtable->magic == TG_HASHTABLE_MAGIC);

	for(i = 0; i < hashtable->bucket_len; i++)
	{
		bucket = &(hashtable->buckets[i]);

		assert(bucket->magic == TG_HASHTABLE_BUCKET_MAGIC);

		RB_FOREACH_SAFE(key, tg_hashtable_rbtree, &bucket->rbtree, next)
		{
			RB_REMOVE(tg_hashtable_rbtree, &bucket->rbtree, key);

			assert(key->magic == TG_HASHTABLE_KEY_MAGIC);

			if(hashtable->callback)
			{
				hashtable->callback(key->value);
			}

			tg_hashtable_key_free(key);

			bucket->size--;
		}

		assert(!bucket->size);

		RB_INIT(&bucket->rbtree);

		bucket->magic = 0;
	}

	if(hashtable->buckets)
	{
		free(hashtable->buckets);

		hashtable->bucket_len = 0;
		hashtable->buckets = NULL;
	}

	hashtable->magic = 0;

	free(hashtable);
}
