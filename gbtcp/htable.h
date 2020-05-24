/* GPL2 license */
#ifndef GBTCP_HTABLE_H
#define GBTCP_HTABLE_H

#include "../bsd44/types.h"
#include "list.h"

typedef uint32_t (*htable_f)(struct dlist *);
typedef void (*htable_foreach_f)(void *);

struct htable_static {
	int hts_size;
	int hts_mask;
	htable_f hts_hash_fn;
	struct dlist *hts_array;
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

#define htable_init htable_static_init
#define htable_deinit htable_static_deinit
#define htable_bucket_get htable_static_bucket_get
#define htable_add htable_static_add
#define htable_del htable_static_del
#define htable_foreach htable_static_foreach
#else
typedef struct htable_dynamic htable_t;

#define htable_init htable_dynamic_init
#define htable_deinit htable_dynamic_deinit
#define htable_bucket_get htable_dynamic_bucket_get
#define htable_add htable_dynamic_add
#define htable_del htable_dynamic_del
#define htable_foreach htable_dynamic_foreach
#endif

int htable_static_init(struct htable_static *, int, htable_f);
void htable_static_deinit(struct htable_static *);
struct dlist *htable_static_bucket_get(struct htable_static *, uint32_t);
void htable_static_add(struct htable_static *, struct dlist *, uint32_t);
void htable_static_del(struct htable_static *, struct dlist *);
void htable_static_foreach(struct htable_static *, htable_foreach_f);

int htable_dynamic_init(struct htable_dynamic *, int, htable_f);
void htable_dynamic_deinit(struct htable_dynamic *);
struct dlist * htable_dynamic_bucket_get(struct htable_dynamic *, uint32_t);
void htable_dynamic_add(struct htable_dynamic *, struct dlist *, uint32_t);
void htable_dynamic_del(struct htable_dynamic *, struct dlist *);
void htable_dynamic_foreach(struct htable_dynamic *, htable_foreach_f);

#endif /* GBTCP_HTABLE_H */
