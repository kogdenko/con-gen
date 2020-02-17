/* GPL2 license */
#include "htable.h"

static int htable_print = 0;

static struct htable_static *htable_dynamic_new(
	struct htable_dynamic *t);
static void htable_dynamic_resize(struct htable_dynamic *t);

int
htable_static_create(struct htable_static *t,
                     int size, htable_hash_f hash_fn)
{
	int i;

	t->hts_size = size;
	t->hts_mask = size - 1;
	t->hts_hash_fn = hash_fn;
	t->hts_array = malloc(size * sizeof(struct dllist));
	if (t->hts_array == NULL) {
		return -ENOMEM;
	}
	t->hts_size = size;
	t->hts_mask = size - 1;
	for (i = 0; i < size; ++i) {
		dllist_init(t->hts_array + i);
	}
	return 0;
}

void
htable_static_free(struct htable_static *t)
{
	free(t->hts_array);
	t->hts_array = NULL;
}

struct dllist *
htable_static_bucket(struct htable_static *t, uint32_t h) 
{
	return t->hts_array + ((h) & (t)->hts_mask);
}

void
htable_static_add(struct htable_static *t, struct dllist *elem, uint32_t h)
{
	struct dllist *bucket;

	bucket = htable_static_bucket(t, h);
	dllist_insert_tail(bucket, elem);
}

void
htable_static_del(struct htable_static *t, struct dllist *elem)
{
	dllist_remove(elem);
}

int
htable_dynamic_create(struct htable_dynamic *t,
                      int size, htable_hash_f hash_fn)
{
	int rc;

	t->htd_size_min = size;
	t->htd_nr_elems = 0;
	t->htd_resize_discard = 0;
	t->htd_old = NULL;
	t->htd_new = t->htd_tables + 0;
	t->htd_tables[1].hts_array = NULL;
	rc = htable_static_create(t->htd_new, size, hash_fn);
	return rc;
}

void
htable_dynamic_free(struct htable_dynamic *t)
{
	int i;

	for (i = 0; i < 2; ++i) {
		htable_static_free(t->htd_tables + i);
	}
}

struct dllist *
htable_dynamic_bucket(struct htable_dynamic *t, uint32_t h) 
{
	int i;
	struct dllist *bucket;
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
	bucket = htable_static_bucket(ts, h);
	return bucket;
}

void
htable_dynamic_add(struct htable_dynamic *t, struct dllist *elem, uint32_t h)
{
	struct dllist *bucket;

	bucket = htable_dynamic_bucket(t, h);
	dllist_insert_tail(bucket, elem);
	t->htd_nr_elems++;
	htable_dynamic_resize(t);
}

void
htable_dynamic_del(struct htable_dynamic *t, struct dllist *elem)
{
	assert(t->htd_nr_elems > 0);
	dllist_remove(elem);
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
	int rc, size, new_size;
	struct dllist *elem, *bucket;
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
		if (t->htd_resize_discard) {
			t->htd_resize_discard--;
			return;
		}
		tmp = htable_dynamic_new(t);
		rc = htable_static_create(tmp, new_size,
		                          t->htd_new->hts_hash_fn);
		if (rc) {
			t->htd_resize_discard = new_size;
			return;
		}
		t->htd_old = t->htd_new;
		t->htd_new = tmp;
		t->htd_resize_progress = 0;
		if (htable_print) {
			printf("htable resize; size=%d->%d, elements=%d\n",
			        size, new_size, t->htd_nr_elems);
		}
	} else {
		assert(t->htd_old->hts_size > t->htd_resize_progress);
		bucket = t->htd_old->hts_array + t->htd_resize_progress;
		while (!dllist_empty(bucket)) {
			elem = dllist_first(bucket);
			dllist_remove(elem);
			h = (*t->htd_new->hts_hash_fn)(elem);
			htable_static_add(t->htd_new, elem, h);
		}
		t->htd_resize_progress++;
		if (t->htd_old->hts_size == t->htd_resize_progress) {
			htable_static_free(t->htd_old);
			t->htd_old = NULL;
			if (htable_print) {
				printf("htable resize done; elements=%d\n",
				       t->htd_nr_elems);
			}
		}
	}
}
