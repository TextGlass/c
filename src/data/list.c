#include "list.h"

tg_list *tg_list_init()
{
	tg_list *list;

	list = malloc(sizeof (tg_list));

	assert(list);

	list->magic = TG_LIST_MAGIC;

	TAILQ_INIT(&list->head);

	list->size = 0;

	assert(!pthread_rwlock_init(&list->rwlock, NULL));

	return list;
}

void tg_list_add(tg_list *list, const void *value)
{
	tg_list_item *add;

	assert(list && list->magic == TG_LIST_MAGIC);
	assert(value);

	assert(!pthread_rwlock_wrlock(&list->rwlock));

	add = malloc(sizeof (tg_list_item));

	assert(add);

	add->magic = TG_LIST_ITEM_MAGIC;

	add->value = value;

	TAILQ_INSERT_TAIL(&list->head, add, entry);

	list->size++;

	assert(!pthread_rwlock_unlock(&list->rwlock));
}

int tg_list_item_valid(tg_list_item *item)
{
	if(!item)
	{
		return 0;
	}
	
	assert(item->magic == TG_LIST_ITEM_MAGIC);

	return 1;
}

int tg_list_rlock(tg_list *list)
{
	assert(list && list->magic == TG_LIST_MAGIC);

	assert(!pthread_rwlock_rdlock(&list->rwlock));

	return 1;
}

int tg_list_unlock(tg_list *list)
{
	assert(list && list->magic == TG_LIST_MAGIC);
	
	assert(!pthread_rwlock_unlock(&list->rwlock));

	return 1;
}

void tg_list_free(tg_list *list)
{
	tg_list_item *item, *next;

	assert(list && list->magic == TG_LIST_MAGIC);

	assert(!pthread_rwlock_wrlock(&list->rwlock));

	TAILQ_FOREACH_SAFE(item, &list->head, entry, next) {
		TAILQ_REMOVE(&list->head, item, entry);
		assert(item->magic == TG_LIST_ITEM_MAGIC);
		item->magic = 0;
		free(item);
		list->size--;
	}

	assert(!list->size);

	TAILQ_INIT(&list->head);

	list->magic = 0;

	assert(!pthread_rwlock_unlock(&list->rwlock));

	assert(!pthread_rwlock_destroy(&list->rwlock));

	free(list);
}
