// SPDX-License-Identifier: GPL-2.0-only

#include "htable.h"
#include "subr.h"

static int htable_print = 0;

static struct htable_static *htable_dynamic_new(
	struct htable_dynamic *t);
static void htable_dynamic_resize(struct htable_dynamic *t);

void
htable_static_init(struct htable_static *t, int size, htable_f hash_fn)
{
	int i;

	t->hts_size = size;
	t->hts_mask = size - 1;
	t->hts_hash_fn = hash_fn;
	t->hts_array = xmalloc(size * sizeof(struct cg_dlist));
	for (i = 0; i < size; ++i) {
		cg_dlist_init(t->hts_array + i);
	}
}

void
htable_static_deinit(struct htable_static *t)
{
	free(t->hts_array);
	t->hts_array = NULL;
}

struct cg_dlist *
htable_static_bucket_get(struct htable_static *t, uint32_t h) 
{
	return t->hts_array + ((h) & (t)->hts_mask);
}

void
htable_static_add(struct htable_static *t, struct cg_dlist *elem, uint32_t h)
{
	struct cg_dlist *bucket;

	bucket = htable_static_bucket_get(t, h);
	cg_dlist_insert_tail(bucket, elem);
}

void
htable_static_del(struct htable_static *t, struct cg_dlist *elem)
{
	cg_dlist_remove(elem);
}

void
htable_static_foreach(struct htable_static *t, void *udata, htable_foreach_f fn)
{
	int i;
	struct cg_dlist *b, *e;

	for (i = 0; i < t->hts_size; ++i) {
		b = t->hts_array + i;
		cg_dlist_foreach(e, b) {
			(*fn)(udata, e);
		}
	}
}

void
htable_dynamic_init(struct htable_dynamic *t, int size, htable_f hash_fn)
{
	t->htd_size_min = size;
	t->htd_nr_elems = 0;
	t->htd_old = NULL;
	t->htd_new = t->htd_tables + 0;
	t->htd_tables[1].hts_array = NULL;
	htable_static_init(t->htd_new, size, hash_fn);
}

void
htable_dynamic_deinit(struct htable_dynamic *t)
{
	int i;

	for (i = 0; i < 2; ++i) {
		htable_static_deinit(t->htd_tables + i);
	}
}

struct cg_dlist *
htable_dynamic_bucket_get(struct htable_dynamic *t, uint32_t h) 
{
	int i;
	struct cg_dlist *bucket;
	struct htable_static *ts;

	if (t->htd_old == NULL) {
		ts = t->htd_new;
	} else {
		i = h & t->htd_old->hts_mask;
		if (i <= t->htd_resize_progress) {
			ts = t->htd_new;
		} else {
			ts = t->htd_old;
		}
	}
	bucket = htable_static_bucket_get(ts, h);
	return bucket;
}

void
htable_dynamic_foreach(struct htable_dynamic *t, void *udata, htable_foreach_f fn)
{
	int i;
	struct cg_dlist *b, *e;

	htable_static_foreach(t->htd_new, udata, fn);
	if (t->htd_old != NULL) {
		for (i = t->htd_resize_progress; i < t->htd_old->hts_size; ++i) {
			b = t->htd_old->hts_array + i;
			cg_dlist_foreach(e, b) {
				(*fn)(udata, e);
			}
		}
	}
}

void
htable_dynamic_add(struct htable_dynamic *t, struct cg_dlist *elem, uint32_t h)
{
	struct cg_dlist *bucket;

	bucket = htable_dynamic_bucket_get(t, h);
	cg_dlist_insert_tail(bucket, elem);
	t->htd_nr_elems++;
	htable_dynamic_resize(t);
}

void
htable_dynamic_del(struct htable_dynamic *t, struct cg_dlist *elem)
{
	assert(t->htd_nr_elems > 0);
	cg_dlist_remove(elem);
	t->htd_nr_elems--;
	htable_dynamic_resize(t);
}

static struct htable_static *
htable_dynamic_new(struct htable_dynamic *t)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(t->htd_tables); ++i) {
		if (t->htd_tables[i].hts_array == NULL) {
			return t->htd_tables + i;
		}
	}
	assert(0);
	return 0;
}

static void
htable_dynamic_resize(struct htable_dynamic *t)
{
	uint32_t h;
	int size, new_size;
	struct cg_dlist *elem, *bucket;
	struct htable_static *tmp;

	if (t->htd_old == NULL) {
		new_size = 0;
		size = t->htd_new->hts_size;
		if (t->htd_nr_elems > size) {
			new_size = size << 1;
		} else if (t->htd_nr_elems < (size >> 2)) {
			new_size = size >> 1;
		}
		if (!new_size) {
			return;
		}
		if (new_size < t->htd_size_min) {
			return;
		}
		tmp = htable_dynamic_new(t);
		htable_static_init(tmp, new_size, t->htd_new->hts_hash_fn);
		t->htd_old = t->htd_new;
		t->htd_new = tmp;
		t->htd_resize_progress = 0;
		if (htable_print) {
			dbg("htable resize: size=%d->%d, elements=%d\n",
				size, new_size, t->htd_nr_elems);
		}
	} else {
		assert(t->htd_old->hts_size > t->htd_resize_progress);
		bucket = t->htd_old->hts_array + t->htd_resize_progress;
		while (!cg_dlist_is_empty(bucket)) {
			elem = cg_dlist_first(bucket);
			cg_dlist_remove(elem);
			h = (*t->htd_new->hts_hash_fn)(elem);
			htable_static_add(t->htd_new, elem, h);
		}
		t->htd_resize_progress++;
		if (t->htd_old->hts_size == t->htd_resize_progress) {
			htable_static_deinit(t->htd_old);
			t->htd_old = NULL;
			if (htable_print) {
				dbg("htable resize done: elements=%d\n", t->htd_nr_elems);
			}
		}
	}
}
