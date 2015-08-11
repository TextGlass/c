#ifndef _TG_LIST_H_INCLUDED_
#define _TG_LIST_H_INCLUDED_

#include <pthread.h>

#include "queue.h"

typedef struct tg_list_item
{
	TAILQ_ENTRY(tg_list_item)	entry;

	const void			*value;
}
tg_list_item;

typedef TAILQ_HEAD(tg_list_head, tg_list_item) tg_list_head;

typedef struct
{
	tg_list_head			head;

	pthread_rwlock_t		rwlock;

	size_t				size;
}
tg_list;


#define tg_list_foreach(list, var)					\
	for (pthread_rwlock_rdlock(&(list)->rwlock),			\
		(var) = TAILQ_FIRST(&(list)->head);			\
		(var) || (pthread_rwlock_unlock(&(list)->rwlock) && 0);	\
		(var) = TAILQ_NEXT((var), entry))

tg_list *tg_list_init();
void tg_list_add(tg_list *list, const void *item);
void tg_list_free(tg_list *list);

#endif  /* _TG_LIST_H_INCLUDED_ */