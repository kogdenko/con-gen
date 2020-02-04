/* GPL2 license */
#ifndef GBTCP_HTABLE_H
#define GBTCP_HTABLE_H

#include "../bsd44/types.h"
#include "list.h"

typedef uint32_t (*htable_hash_f)(struct dllist *);

struct htable_static {
	int hts_size;
	int hts_mask;
	htable_hash_f hts_hash_fn;
	struct dllist *hts_array;
};

struct htable_dynamic {
	struct htable_static *htd_new;
	struct htable_static *htd_old;
	int htd_size_min;
	int htd_nr_elems;
	int htd_resize_discard;
	int htd_resize_progress;
	struct htable_static htd_tables[2];
};

#if 0
typedef struct htable_static htable_t;

#define htable_create htable_static_create
#define htable_free htable_static_free
#define htable_bucket htable_static_bucket
#define htable_add htable_static_add
#define htable_del htable_static_del
#else
typedef struct htable_dynamic htable_t;

#define htable_create htable_dynamic_create
#define htable_free htable_dynamic_free
#define htable_bucket htable_dynamic_bucket
#define htable_add htable_dynamic_add
#define htable_del htable_dynamic_del
#endif

int htable_static_create(struct htable_static *t, int, htable_hash_f);

void htable_static_free(struct htable_static *);

struct dllist *htable_static_bucket(struct htable_static *, uint32_t);

void htable_static_add(struct htable_static *t, struct dllist *, uint32_t);

void htable_static_del(struct htable_static *t, struct dllist *);

int htable_dynamic_create(struct htable_dynamic *, int, htable_hash_f);

void htable_dynamic_free(struct htable_dynamic *);

struct dllist * htable_dynamic_bucket(struct htable_dynamic *, uint32_t);

void htable_dynamic_add(struct htable_dynamic *, struct dllist *, uint32_t);

void htable_dynamic_del(struct htable_dynamic *, struct dllist *);

#endif /* GBTCP_HTABLE_H */
