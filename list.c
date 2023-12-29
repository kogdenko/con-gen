// SPDX-License-Identifier: GPL-2.0-only

#include "list.h"

void
cg_dlist_init(struct  cg_dlist *head)
{
	head->dls_next = head->dls_prev = head;
}

int
cg_dlist_size(struct cg_dlist *head)
{
	int size;
	struct cg_dlist *cur;

	size = 0;
	cg_dlist_foreach(cur, head) {
		size++;
	}
	return size;
}

int
cg_dlist_is_empty(struct cg_dlist *head)
{
	return head->dls_next == head;
}

struct cg_dlist *
cg_dlist_first(struct cg_dlist *head)
{
	return head->dls_next;
}

struct cg_dlist *
cg_dlist_last(struct cg_dlist *head)
{
	return head->dls_prev;
}

void
cg_dlist_insert_head(struct cg_dlist *head, struct cg_dlist *l)
{
	l->dls_next = head->dls_next;
	l->dls_prev = head;
	head->dls_next->dls_prev = l;
	head->dls_next = l;
}

void
cg_dlist_insert_tail(struct cg_dlist *head, struct cg_dlist *l)
{
	l->dls_next = head;
	l->dls_prev = head->dls_prev;
	head->dls_prev->dls_next = l;
	head->dls_prev = l;
}

void
cg_dlist_remove(struct cg_dlist *list)
{
	list->dls_next->dls_prev = list->dls_prev;
	list->dls_prev->dls_next = list->dls_next;
}
