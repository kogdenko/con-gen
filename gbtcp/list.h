/* GPL2 license */
#ifndef GBTCP_LIST_H
#define GBTCP_LIST_H

#include "./sys/types.h"

/* Double linked list */
struct dllist {
	struct dllist *dls_next;
	struct dllist *dls_prev;
};

void dllist_init(struct  dllist *head);

int dllist_size(struct dllist *head);

int dllist_empty(struct dllist *head);

struct dllist *dllist_first(struct dllist *head);

struct dllist *dllist_last(struct dllist *head);

void dllist_insert_head(struct dllist *head, struct dllist *l);

void dllist_insert_tail(struct dllist *head, struct dllist *l);

void dllist_insert_before(struct dllist *b, struct dllist *l);

void dllist_insert_after(struct dllist *a, struct dllist *l);

void dllist_remove(struct dllist *list);

#define DLLIST_HEAD_INIT(name) { &name, &name }

#define DLLIST_HEAD(name) struct dllist name = DLLIST_HEAD_INIT(name)

#define DLLIST_FIRST(head, type, field) \
	container_of((head)->dls_next, type, field)

#define DLLIST_LAST(head, type, field) \
	container_of((head)->dls_prev, type, field)

#define DLLIST_NEXT(var, field) \
	container_of((var)->field.dls_next, __typeof__(*(var)), field)

#define DLLIST_INSERT_HEAD(head, var, field) \
	dllist_insert_head(head, &((var)->field))

#define DLLIST_INSERT_TAIL(head, var, field) \
	dllist_insert_tail(head, &((var)->field))

#define DLLIST_INSERT_BEFORE(bvar, var, field) \
	dllist_insert_before(&((bvar)->field), &((var)->field))

#define DLLIST_INSERT_AFTER(avar, var, field) \
	dllist_insert_after(&((avar)->field), &((var)->field))

#define DLLIST_REMOVE(var, field) \
	dllist_remove(&(var)->field)

#define dllist_foreach(var, head) \
	for (var = (head)->dls_next; var != (head); var = var->dls_next)

#define DLLIST_FOREACH(var, head, field) \
	for (var = DLLIST_FIRST(head, typeof(*(var)), field); \
		&((var)->field) != (head); \
		var = DLLIST_NEXT(var, field))

#define DLLIST_FOREACH_CONTINUE(pos, head, field) \
	for (; &((pos)->field) != (head); \
		pos = DLLIST_NEXT(pos, field))

#define DLLIST_FOREACH_SAFE(var, head, field, tvar) \
	for (var = DLLIST_FIRST(head, typeof(*(var)), field); \
		(&((var)->field) != (head)) && \
		((tvar = DLLIST_NEXT(var, field)), 1); \
		var = tvar)

#endif /* GBTCP_LIST_H */
