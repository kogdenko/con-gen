// SPDX-License-Identifier: GPL-2.0-only

#ifndef CONGEN_LIST_H
#define CONGEN_LIST_H

// Double linked list
struct cg_dlist {
	struct cg_dlist *dls_next;
	struct cg_dlist *dls_prev;
};

#define cg_field_off(type, field) ((intptr_t)&((type *)0)->field)
#define cg_container_of(ptr, type, field) \
	((type *)((intptr_t)(ptr) - cg_field_off(type, field)))

void cg_dlist_init(struct  cg_dlist *);
int cg_dlist_size(struct cg_dlist *);
int cg_dlist_is_empty(struct cg_dlist *);
struct cg_dlist *cg_dlist_first(struct cg_dlist *);
struct cg_dlist *cg_dlist_last(struct cg_dlist *);
void cg_dlist_insert_head(struct cg_dlist *, struct cg_dlist *);
void cg_dlist_insert_tail(struct cg_dlist *, struct cg_dlist *);
void cg_dlist_remove(struct cg_dlist *);

#define CG_DLIST_HEAD_INIT(name) { &name, &name }

#define CG_DLIST_HEAD(name) struct cg_dlist name = CG_DLIST_HEAD_INIT(name)

#define CG_DLIST_FIRST(head, type, field) \
	cg_container_of((head)->dls_next, type, field)

#define CG_DLIST_LAST(head, type, field) \
	cg_container_of((head)->dls_prev, type, field)

#define CG_DLIST_NEXT(var, field) \
	cg_container_of((var)->field.dls_next, __typeof__(*(var)), field)

#define CG_DLIST_INSERT_HEAD(head, var, field) \
	cg_dlist_insert_head(head, &((var)->field))

#define CG_DLIST_INSERT_TAIL(head, var, field) \
	cg_dlist_insert_tail(head, &((var)->field))

#define CG_DLIST_REMOVE(var, field) \
	cg_dlist_remove(&(var)->field)

#define cg_dlist_foreach(var, head) \
	for (var = (head)->dls_next; var != (head); var = var->dls_next)

#define CG_DLIST_FOREACH(var, head, field) \
	for (var = CG_DLIST_FIRST(head, typeof(*(var)), field); \
		&((var)->field) != (head); \
		var = CG_DLIST_NEXT(var, field))

#define CG_DLIST_FOREACH_CONTINUE(pos, head, field) \
	for (; &((pos)->field) != (head); \
		pos = CG_DLIST_NEXT(pos, field))

#define CG_DLIST_FOREACH_SAFE(var, head, field, tvar) \
	for (var = CG_DLIST_FIRST(head, typeof(*(var)), field); \
		(&((var)->field) != (head)) && \
		((tvar = CG_DLIST_NEXT(var, field)), 1); \
		var = tvar)

#endif // CONGEN_LIST_H
