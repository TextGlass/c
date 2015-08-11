#include <stdio.h>

#include "hashtable.h"
#include "list.h"

int main(int argc, char **args)
{
	tg_hashtable *hashtable;

	printf("TextGlass\n");

	hashtable = tg_hashtable_init(2);

	tg_hashtable_set(hashtable, "1", "one");
	tg_hashtable_set(hashtable, "2", "two");
	tg_hashtable_set(hashtable, "3", "three");
	tg_hashtable_set(hashtable, "4", "four");

	printf("tg_hashtable: %s\n", (char*)tg_hashtable_get(hashtable, "1"));
	printf("tg_hashtable: %s\n", (char*)tg_hashtable_get(hashtable, "2"));
	printf("tg_hashtable: %s\n", (char*)tg_hashtable_get(hashtable, "3"));
	printf("tg_hashtable: %s\n", (char*)tg_hashtable_get(hashtable, "4"));
	
	tg_hashtable_delete(hashtable, "3");

	printf("tg_hashtable: %s\n", (char*)tg_hashtable_get(hashtable, "3"));

	tg_hashtable_free(hashtable);

	tg_list *list;
	tg_list_item *item;

	list = tg_list_init();

	tg_list_add(list, "aaa");
	tg_list_add(list, "bbb");
	tg_list_add(list, "ccc");
	tg_list_add(list, "ddd");

	tg_list_foreach(list, item)
	{
		printf("tg_list: %s\n", (char*)item->value);
	}

	tg_list_free(list);
	
	return 0;
}
