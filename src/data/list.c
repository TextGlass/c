#include "list.h"

tg_list *tg_list_init()
{
	tg_list *list;

	list = malloc(sizeof (tg_list));

	assert(list);

	TAILQ_INIT(&list->head);

	list->size = 0;

	assert(!pthread_rwlock_init(&list->rwlock, NULL));

	return list;
}

void tg_list_add(tg_list *list, const void *value)
{
	tg_list_item *add;

	assert(list);
	assert(value);

	assert(!pthread_rwlock_wrlock(&list->rwlock));

	add = malloc(sizeof (tg_list_item));

	assert(add);

	add->value = value;

	TAILQ_INSERT_TAIL(&list->head, add, entry);

	list->size++;

	assert(!pthread_rwlock_unlock(&list->rwlock));
}

void tg_list_free(tg_list *list)
{
	tg_list_item *item, *next;

	assert(list);

	assert(!pthread_rwlock_wrlock(&list->rwlock));

	TAILQ_FOREACH_SAFE(item, &list->head, entry, next) {
		TAILQ_REMOVE(&list->head, item, entry);
		free(item);
		list->size--;
	}

	assert(!list->size);

	TAILQ_INIT(&list->head);

	assert(!pthread_rwlock_unlock(&list->rwlock));

	assert(!pthread_rwlock_destroy(&list->rwlock));

	free(list);
}
