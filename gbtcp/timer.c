// gpl2 license
#include "timer.h"
#include "../global.h"

#define TIMER_RING_ID_MASK (((uintptr_t)1 << TIMER_RING_ID_SHIFT) - 1)
#define TIMER_RING_MAX (1 << TIMER_RING_ID_SHIFT)

struct timer_ring {
	uint64_t r_seg_shift;
	uint64_t r_pos;
	int r_ntimers;
	struct dlist r_segs[TIMER_RING_SIZE];
};

static __thread int n_timer_rings;
static __thread struct timer_ring *timer_rings[TIMER_RING_MAX];

static int
alloc_timer_rings(void)
{
	int i;

	for (i = 0; i < n_timer_rings; ++i) {
		timer_rings[i] = xmalloc(sizeof(struct timer_ring));
	}
	return 0;
}

static void
free_timer_rings(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(timer_rings); ++i) {
		free(timer_rings[i]);
		timer_rings[i] = NULL;
	}
}

static int
ffs64(uint64_t x)
{
	int i;
	uint64_t bit;

	bit = 1;
	for (i = 0; i < 64; ++i) {
		if ((bit << i) & x) {
			return i + 1;
		}
	}
	return 0;
}

static void
timer_ring_init(struct timer_ring *ring, uint64_t seg_size)
{
	int i;

	if (seg_size) {
		ring->r_seg_shift = ffs64(seg_size) - 1;
		assert(seg_size == (1llu << ring->r_seg_shift));
		ring->r_pos = current->t_time >> ring->r_seg_shift;
	}
	ring->r_ntimers = 0;
	for (i = 0; i < TIMER_RING_SIZE; ++i) {
		dlist_init(ring->r_segs + i);
	}
}

int
init_timers(void)
{
	int i;
	uint64_t seg_size;
	uint64_t seg_sizes[TIMER_RING_MAX];
	struct timer_ring *ring;

	seg_size = 1llu << 25; // 33554432 ~ 33ms
	n_timer_rings = 0;
	while (seg_size < TIMER_EXPIRE_MAX) {
		seg_sizes[n_timer_rings] = seg_size;
		n_timer_rings++;
		if (seg_size * TIMER_RING_SIZE > TIMER_EXPIRE_MAX) {
			break;
		} else {
			seg_size = ((seg_size * TIMER_RING_SIZE) >> 2llu);
			assert(n_timer_rings < TIMER_RING_MAX);
		}
	}
	assert(n_timer_rings);
	alloc_timer_rings();
	for (i = 0; i < n_timer_rings; ++i) {
		ring = timer_rings[i];
		timer_ring_init(ring, seg_sizes[i]);
	}
	return 0;
}

void
deinit_timers(void)
{
	free_timer_rings();
}

void
timer_init(struct timer *timer)
{
	timer->tm_data = 0;
}

int
timer_is_running(struct timer *timer)
{
	return timer->tm_data != 0;
}

void
timer_set(struct timer *timer, uint64_t expire, timer_f fn)
{
	int ring_id;
	uintptr_t uint_fn;
	uint64_t dist, pos;
	struct dlist *seg;
	struct timer_ring *ring;

	uint_fn = (uintptr_t)fn;
	assert(uint_fn != 0);
	assert((uint_fn & TIMER_RING_ID_MASK) == 0);
	assert(expire <= TIMER_EXPIRE_MAX);
	timer_cancel(timer);
	dist = 0;
	for (ring_id = 0; ring_id < n_timer_rings; ++ring_id) {
		ring = timer_rings[ring_id];
		dist = expire >> ring->r_seg_shift;
		assert(dist >= 2);
		if (dist < TIMER_RING_SIZE) {
			break;
		}
	}
	if (ring_id == n_timer_rings) {
		ring_id = n_timer_rings - 1;
		ring = timer_rings[ring_id];
		dist = TIMER_RING_SIZE - 1;
	}
	assert((ring_id & ~TIMER_RING_ID_MASK) == 0);
	ring = timer_rings[ring_id];
	pos = ring->r_pos + dist;
	seg = ring->r_segs + (pos & TIMER_RING_MASK);
	ring->r_ntimers++;
	timer->tm_data = uint_fn|ring_id;
	DLIST_INSERT_HEAD(seg, timer, tm_list);
}

void
timer_cancel(struct timer *timer)
{
	int ring_id;
	struct timer_ring *ring;

	if (timer_is_running(timer)) {
		ring_id = timer->tm_data & TIMER_RING_ID_MASK;
		ring = timer_rings[ring_id];
		ring->r_ntimers--;
		assert(ring->r_ntimers >= 0);
		DLIST_REMOVE(timer, tm_list);
		timer->tm_data = 0;
	}
}

static void
call_timers(struct dlist *q)
{
	struct timer *timer;
	timer_f fn;

	while (!dlist_is_empty(q)) {
		timer = DLIST_FIRST(q, struct timer, tm_list);
		DLIST_REMOVE(timer, tm_list);
		fn = (timer_f)(timer->tm_data & ~TIMER_RING_ID_MASK);
		timer->tm_data = 0;
		(*fn)(timer);
	}
}

static void
check_timer_ring(struct timer_ring *ring, struct dlist *q)
{
	int i;
	uint64_t pos;
	struct timer *timer;
	struct dlist *seg;

	pos = ring->r_pos;
	ring->r_pos = (current->t_time >> ring->r_seg_shift);
	assert(pos <= ring->r_pos);
	if (ring->r_ntimers == 0) {
		return;
	}
	for (i = 0; pos <= ring->r_pos && i < TIMER_RING_SIZE; ++pos, ++i) {
		seg = ring->r_segs + (pos & TIMER_RING_MASK);
		while (!dlist_is_empty(seg)) {
			ring->r_ntimers--;
			assert(ring->r_ntimers >= 0);
			timer = DLIST_FIRST(seg, struct timer, tm_list);
			DLIST_REMOVE(timer, tm_list);
			DLIST_INSERT_HEAD(q, timer, tm_list);
		}
		if (ring->r_ntimers == 0) {
			break;
		}
	}
}

void
check_timers(void)
{
	int i;
	static __thread uint64_t last_check_time;
	struct dlist q;
	struct timer_ring *ring;

	if (current->t_time - last_check_time < 30 * NANOSECONDS_MILLISECOND) {
		return;
	}
	last_check_time = current->t_time;
	dlist_init(&q);
	for (i = 0; i < n_timer_rings; ++i) {
		ring = timer_rings[i];
		check_timer_ring(ring, &q);
	}
	call_timers(&q);
}
