#include "list.h"

tg_list *tg_list_alloc(size_t initial_len, void (*free)(void *item))
{
	tg_list *list;

	if(initial_len > TG_LIST_PREALLOC)
	{
		initial_len -= TG_LIST_PREALLOC;
	}
	else
	{
		initial_len = 0;
	}

	list = calloc(1, sizeof(tg_list) + (sizeof(tg_list_item) * initial_len));

	assert(list);

	tg_list_init(list, initial_len, free);
	
	list->malloc = 1;

	TAILQ_INIT(&list->head);

	return list;
}

void tg_list_init(tg_list * list, size_t initial_len, void (*free)(void *item))
{
	assert(list && list->magic != TG_LIST_MAGIC);

	list->magic = TG_LIST_MAGIC;
	list->size = 0;
	list->prealloc_len = TG_LIST_PREALLOC + initial_len;
	list->callback = free;
	list->malloc = 0;

	TAILQ_INIT(&list->head);
}

static tg_list_item *tg_list_item_alloc(tg_list *list)
{
	tg_list_item *item;

	if(list->size < list->prealloc_len)
	{
		item = &list->prealloc[list->size];

		assert(item->magic != TG_LIST_ITEM_MAGIC);

		item->magic = TG_LIST_ITEM_MAGIC;
		item->malloc = 0;

		return item;
	}

	item = malloc(sizeof(tg_list_item));

	assert(item);

	item->magic = TG_LIST_ITEM_MAGIC;
	item->malloc = 1;

	return item;
}

void tg_list_add(tg_list *list, void *value)
{
	tg_list_item *add;

	assert(list && list->magic == TG_LIST_MAGIC);
	assert(value);

	add = tg_list_item_alloc(list);

	add->value = value;

	TAILQ_INSERT_TAIL(&list->head, add, entry);

	list->size++;
}

void *tg_list_get(tg_list *list, size_t index)
{
	tg_list_item *item;

	assert(list && list->magic == TG_LIST_MAGIC);

	TG_LIST_FOREACH(list, item)
	{
		if(!index)
		{
			return item->value;
		}

		index--;
	}

	return NULL;
}

long tg_list_index_str(tg_list *list, char *value)
{
	long i = 0;
	tg_list_item *item;

	assert(list && list->magic == TG_LIST_MAGIC);
	assert(value);

	TG_LIST_FOREACH(list, item)
	{
		if(!strcmp(value, (char*)item->value))
		{
			return i;
		}

		i++;
	}

	return -1;
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

void tg_list_free(tg_list *list)
{
	tg_list_item *item, *next;

	assert(list && list->magic == TG_LIST_MAGIC);

	TAILQ_FOREACH_SAFE(item, &list->head, entry, next) {
		TAILQ_REMOVE(&list->head, item, entry);

		assert(item->magic == TG_LIST_ITEM_MAGIC);

		if(list->callback)
		{
			list->callback(item->value);
		}

		item->magic = 0;

		if(item->malloc)
		{
			free(item);
		}

		list->size--;
	}

	assert(!list->size);

	TAILQ_INIT(&list->head);

	list->magic = 0;

	if(list->malloc)
	{
		free(list);
	}
}
