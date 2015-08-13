#ifndef _TG_LIST_H_INCLUDED_
#define _TG_LIST_H_INCLUDED_

#include <stdlib.h>
#include <assert.h>
#include <pthread.h>

#include "queue.h"

typedef struct tg_list_item
{
	unsigned int			magic;
#define	TG_LIST_ITEM_MAGIC		0xADFFC5D5

	TAILQ_ENTRY(tg_list_item)	entry;

	void				*value;

	int				malloc:1;
}
tg_list_item;

typedef TAILQ_HEAD(tg_list_head, tg_list_item) tg_list_head;

typedef struct
{
	unsigned int			magic;
#define	TG_LIST_MAGIC			0xF3E27755

	tg_list_head			head;

	void				(*callback)(void*);

	pthread_rwlock_t		rwlock;

	size_t				size;
	size_t				prealloc_len;

	tg_list_item			prealloc[0];
}
tg_list;


#define tg_list_foreach_lock(list, var)			\
	for (tg_list_rlock(list),			\
		(var) = TAILQ_FIRST(&(list)->head);	\
		tg_list_item_valid(var) ||		\
		(tg_list_unlock(list) && 0);		\
		(var) = TAILQ_NEXT((var), entry))

#define tg_list_foreach(list, var)			\
	for ((var) = TAILQ_FIRST(&(list)->head);	\
		tg_list_item_valid(var);		\
		(var) = TAILQ_NEXT((var), entry))

tg_list *tg_list_init(size_t initial_len, void (*free)(void *item));
void tg_list_add(tg_list *list, void *item);
void tg_list_free(tg_list *list);
int tg_list_item_valid(tg_list_item *item);
int tg_list_rlock(tg_list *list);
int tg_list_unlock(tg_list *list);

#endif  /* _TG_LIST_H_INCLUDED_ */