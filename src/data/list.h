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

	const void			*value;
}
tg_list_item;

typedef TAILQ_HEAD(tg_list_head, tg_list_item) tg_list_head;

typedef struct
{
	unsigned int			magic;
#define	TG_LIST_MAGIC			0xF3E27755

	tg_list_head			head;

	pthread_rwlock_t		rwlock;

	size_t				size;
}
tg_list;


#define tg_list_foreach(list, var)			\
	for (tg_list_rlock(list),			\
		(var) = TAILQ_FIRST(&(list)->head);	\
		tg_list_item_valid(var) ||		\
		(tg_list_unlock(list) && 0);		\
		(var) = TAILQ_NEXT((var), entry))

tg_list *tg_list_init();
void tg_list_add(tg_list *list, const void *item);
void tg_list_free(tg_list *list);
int tg_list_item_valid(tg_list_item *item);
int tg_list_rlock(tg_list *list);
int tg_list_unlock(tg_list *list);

#endif  /* _TG_LIST_H_INCLUDED_ */