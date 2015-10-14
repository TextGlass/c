/*
 * Copyright (c) 2015 TextGlass
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */

#ifndef _TG_LIST_H_INCLUDED_
#define _TG_LIST_H_INCLUDED_

#include <stdlib.h>
#include <string.h>

#ifndef _TEXTGLASS_SKIP_ASSERT
#include <assert.h>
#endif

#include "queue.h"


#define TG_LIST_PREALLOC		3


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

	size_t				size;
	size_t				prealloc_len;

	int				malloc:1;

	tg_list_item			prealloc[TG_LIST_PREALLOC];
}
tg_list;


#define TG_LIST_FOREACH(list, var)			\
	for ((var) = TAILQ_FIRST(&(list)->head);	\
		tg_list_item_valid(var);		\
		(var) = TAILQ_NEXT((var), entry))


tg_list *tg_list_alloc(size_t initial_len, void (*callback)(void *item));
void tg_list_init(tg_list * list, size_t initial_len, void (*callback)(void *item));
void tg_list_add(tg_list *list, void *item);
void *tg_list_get(tg_list *list, size_t index);
void *tg_list_get_from(tg_list_item *item, size_t index);
long tg_list_index_str(tg_list *list, const char *value);
void tg_list_free(tg_list *list);
int tg_list_item_valid(tg_list_item *item);


#endif  /* _TG_LIST_H_INCLUDED_ */
