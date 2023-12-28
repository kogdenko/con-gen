// GPL v2 license
#ifndef CON_GEN__GBTCP__LIST_H
#define CON_GEN__GBTCP__LIST_H

// Double linked list
struct dlist {
	struct dlist *dls_next;
	struct dlist *dls_prev;
};

#define cg_field_off(type, field) ((intptr_t)&((type *)0)->field)
#define cg_container_of(ptr, type, field) \
	((type *)((intptr_t)(ptr) - cg_field_off(type, field)))

void dlist_init(struct  dlist *);
int dlist_size(struct dlist *);
int dlist_is_empty(struct dlist *);
struct dlist *dlist_first(struct dlist *);
struct dlist *dlist_last(struct dlist *);
void dlist_insert_head(struct dlist *, struct dlist *);
void dlist_insert_tail(struct dlist *, struct dlist *);
void dlist_remove(struct dlist *);

#define DLIST_HEAD_INIT(name) { &name, &name }

#define DLIST_HEAD(name) struct dlist name = DLIST_HEAD_INIT(name)

#define DLIST_FIRST(head, type, field) \
	cg_container_of((head)->dls_next, type, field)

#define DLIST_LAST(head, type, field) \
	cg_container_of((head)->dls_prev, type, field)

#define DLIST_NEXT(var, field) \
	cg_container_of((var)->field.dls_next, __typeof__(*(var)), field)

#define DLIST_INSERT_HEAD(head, var, field) \
	dlist_insert_head(head, &((var)->field))

#define DLIST_INSERT_TAIL(head, var, field) \
	dlist_insert_tail(head, &((var)->field))

#define DLIST_REMOVE(var, field) \
	dlist_remove(&(var)->field)

#define dlist_foreach(var, head) \
	for (var = (head)->dls_next; var != (head); var = var->dls_next)

#define DLIST_FOREACH(var, head, field) \
	for (var = DLIST_FIRST(head, typeof(*(var)), field); \
		&((var)->field) != (head); \
		var = DLIST_NEXT(var, field))

#define DLIST_FOREACH_CONTINUE(pos, head, field) \
	for (; &((pos)->field) != (head); \
		pos = DLIST_NEXT(pos, field))

#define DLIST_FOREACH_SAFE(var, head, field, tvar) \
	for (var = DLIST_FIRST(head, typeof(*(var)), field); \
		(&((var)->field) != (head)) && \
		((tvar = DLIST_NEXT(var, field)), 1); \
		var = tvar)

#endif // CON_GEN__GBTCP__LIST_H
