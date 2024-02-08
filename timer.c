// gpl2 license
#include "timer.h"
#include "subr.h"

#define CG_TIMER_RING_MAX 16

struct cg_timer_ring {
	uint64_t r_seg_shift;
	uint64_t r_pos;
	int r_n_timers;
	struct dlist r_segs[CG_TIMER_RING_SIZE];
};

static void
alloc_timer_rings(struct cg_task *t)
{
	assert(t->t_n_timer_rings);
	t->t_timer_rings = xmalloc(sizeof(struct cg_timer_ring) * t->t_n_timer_rings);
}

static struct cg_timer_ring *
get_timer_ring(struct cg_task *t, int ring_id)
{
	assert(ring_id < t->t_n_timer_rings);
	return t->t_timer_rings + ring_id;
}

static void
timer_ring_init(struct cg_task *t, struct cg_timer_ring *ring, uint64_t seg_size)
{
	int i;

	if (seg_size) {
		ring->r_seg_shift = ffs64(seg_size) - 1;
		assert(seg_size == (1llu << ring->r_seg_shift));
		ring->r_pos = t->t_time >> ring->r_seg_shift;
	}

	ring->r_n_timers = 0;
	for (i = 0; i < CG_TIMER_RING_SIZE; ++i) {
		dlist_init(ring->r_segs + i);
	}
}

void
cg_init_timers(struct cg_task *t)
{
	int i;
	uint64_t seg_size;
	uint64_t seg_sizes[CG_TIMER_RING_MAX];
	struct cg_timer_ring *ring;

	seg_size = 1llu << 25; // 33554432 ~ 33ms
	t->t_n_timer_rings = 0;
	while (seg_size < CG_TIMER_EXPIRE_MAX) {
		seg_sizes[t->t_n_timer_rings] = seg_size;
		t->t_n_timer_rings++;
		if (seg_size * CG_TIMER_RING_SIZE > CG_TIMER_EXPIRE_MAX) {
			break;
		} else {
			seg_size = ((seg_size * CG_TIMER_RING_SIZE) >> 2llu);
			assert(t->t_n_timer_rings < CG_TIMER_RING_MAX);
		}
	}

	alloc_timer_rings(t);
	for (i = 0; i < t->t_n_timer_rings; ++i) {
		ring = get_timer_ring(t, i);
		timer_ring_init(t, ring, seg_sizes[i]);
	}
}

void
cg_deinit_timers(struct cg_task *t)
{
	free(t->t_timer_rings);
}

void
timer_init(struct timer *timer)
{
	timer->tm_fn = NULL;
}

int
timer_is_running(struct timer *timer)
{
	return timer->tm_fn != NULL;
}

void
timer_set(struct cg_task *t, struct timer *timer, uint64_t expire, timer_f fn)
{
	int ring_id;
	uint64_t dist, pos;
	struct dlist *seg;
	struct cg_timer_ring *ring;

	assert(fn != NULL);
	assert(expire <= CG_TIMER_EXPIRE_MAX);

	timer_cancel(t, timer);

	dist = 0;
	for (ring_id = 0; ring_id < t->t_n_timer_rings; ++ring_id) {
		ring = get_timer_ring(t, ring_id);
		dist = expire >> ring->r_seg_shift;
		assert(dist >= 2);
		if (dist < CG_TIMER_RING_SIZE) {
			break;
		}
	}
	if (ring_id == t->t_n_timer_rings) {
		ring_id = t->t_n_timer_rings - 1;
		ring = get_timer_ring(t, ring_id);
		dist = CG_TIMER_RING_SIZE - 1;
	}

	ring = get_timer_ring(t, ring_id);
	pos = ring->r_pos + dist;
	seg = ring->r_segs + (pos & CG_TIMER_RING_MASK);
	ring->r_n_timers++;
	timer->tm_fn = fn;
	timer->tm_ring_id = ring_id;
	DLIST_INSERT_HEAD(seg, timer, tm_list);
}

void
timer_cancel(struct cg_task *t, struct timer *timer)
{
	struct cg_timer_ring *ring;

	if (timer_is_running(timer)) {
		ring = get_timer_ring(t, timer->tm_ring_id);
		ring->r_n_timers--;
		assert(ring->r_n_timers >= 0);
		DLIST_REMOVE(timer, tm_list);
		timer->tm_fn = NULL;
	}
}

static void
call_timers(struct cg_task *t, struct dlist *q)
{
	struct timer *timer;
	timer_f fn;

	while (!dlist_is_empty(q)) {
		timer = DLIST_FIRST(q, struct timer, tm_list);
		DLIST_REMOVE(timer, tm_list);
		fn = timer->tm_fn;
		timer->tm_fn = NULL;
		(*fn)(t, timer);
	}
}

static void
check_timer_ring(struct cg_task *t, struct cg_timer_ring *ring, struct dlist *q)
{
	int i;
	uint64_t pos;
	struct timer *timer;
	struct dlist *seg;

	pos = ring->r_pos;
	ring->r_pos = (t->t_time >> ring->r_seg_shift);
	assert(pos <= ring->r_pos);
	if (ring->r_n_timers == 0) {
		return;
	}
	for (i = 0; pos <= ring->r_pos && i < CG_TIMER_RING_SIZE; ++pos, ++i) {
		seg = ring->r_segs + (pos & CG_TIMER_RING_MASK);
		while (!dlist_is_empty(seg)) {
			ring->r_n_timers--;
			assert(ring->r_n_timers >= 0);
			timer = DLIST_FIRST(seg, struct timer, tm_list);
			DLIST_REMOVE(timer, tm_list);
			DLIST_INSERT_HEAD(q, timer, tm_list);
		}
		if (ring->r_n_timers == 0) {
			break;
		}
	}
}

void
cg_check_timers(struct cg_task *t)
{
	int i;
	struct dlist q;
	struct cg_timer_ring *ring;

	if (t->t_time - t->t_timers_last_time < 30 * NANOSECONDS_MILLISECOND) {
		return;
	}
	t->t_timers_last_time = t->t_time;

	dlist_init(&q);
	for (i = 0; i < t->t_n_timer_rings; ++i) {
		ring = get_timer_ring(t, i);
		check_timer_ring(t, ring, &q);
	}
	call_timers(t, &q);
}
