/* GPL2 license */
#include "list.h"

void
dlist_init(struct  dlist *head)
{
	head->dls_next = head->dls_prev = head;
}

int
dlist_size(struct dlist *head)
{
	int size;
	struct dlist *cur;

	size = 0;
	dlist_foreach(cur, head) {
		size++;
	}
	return size;
}

int
dlist_is_empty(struct dlist *head)
{
	return head->dls_next == head;
}

struct dlist *
dlist_first(struct dlist *head)
{
	return head->dls_next;
}

struct dlist *
dlist_last(struct dlist *head)
{
	return head->dls_prev;
}

void
dlist_insert_head(struct dlist *head, struct dlist *l)
{
	l->dls_next = head->dls_next;
	l->dls_prev = head;
	head->dls_next->dls_prev = l;
	head->dls_next = l;
}

void
dlist_insert_tail(struct dlist *head, struct dlist *l)
{
	l->dls_next = head;
	l->dls_prev = head->dls_prev;
	head->dls_prev->dls_next = l;
	head->dls_prev = l;
}

void
dlist_remove(struct dlist *list)
{
	list->dls_next->dls_prev = list->dls_prev;
	list->dls_prev->dls_next = list->dls_next;
}
