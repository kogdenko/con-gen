/* GPL2 license */
#include "timer.h"

#define TIMERRING_ID_MASK (((uintptr_t)1 << TIMERRING_ID_SHIFT) - 1)
#define TIMERRING_MAX (1 << TIMERRING_ID_SHIFT)

struct timerring {
	uint64_t r_seg_shift;
	uint64_t r_pos;
	int r_ntimers;
	struct dlist r_segs[TIMERRING_SIZE];
};

static int ntimerrings;
static uint64_t timer_lasttime;
static struct timerring *timerrings[TIMERRING_MAX];

static int timerring_getid(struct timer *);

static int timer_allocrings();

static void timer_freerings();

static void timerring_init(struct timerring *, uint64_t);

static void timer_callq(struct dlist *);

static void timerring_checktimo(struct timerring *, struct dlist *);

static int
timerring_getid(struct timer *timer)
{
	return timer->tm_data & TIMERRING_ID_MASK;
}

static int
timer_allocrings()
{
	int i;

	for (i = 0; i < ntimerrings; ++i) {
		timerrings[i] = malloc(sizeof(struct timerring));
		if (timerrings[i] == NULL) {
			timer_freerings();
			return -ENOMEM;
		}
	}
	return 0;
}

static void
timer_freerings()
{
	int i;

	for (i = 0; i < ARRAY_SIZE(timerrings); ++i) {
		free(timerrings[i]);
		timerrings[i] = NULL;
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
timerring_init(struct timerring *ring, uint64_t seg_size)
{
	int i;

	if (seg_size) {
		ring->r_seg_shift = ffs64(seg_size) - 1;
		assert(seg_size == (1llu << ring->r_seg_shift));
		ring->r_pos = nanosec >> ring->r_seg_shift;
	}
	ring->r_ntimers = 0;
	for (i = 0; i < TIMERRING_SIZE; ++i) {
		dlist_init(ring->r_segs + i);
	}
}

int
timer_modinit()
{
	int i, rc;
	uint64_t seg_size;
	uint64_t seg_sizes[TIMERRING_MAX];
	struct timerring *ring;

	seg_size = 1llu << 25; // 33554432 ~ 33ms
	ntimerrings = 0;
	while (seg_size < TIMER_EXPIREMAX) {
		seg_sizes[ntimerrings] = seg_size;
		ntimerrings++;
		if (seg_size * TIMERRING_SIZE > TIMER_EXPIREMAX) {
			break;
		} else {
			seg_size = ((seg_size * TIMERRING_SIZE) >> 2llu);
			assert(ntimerrings < TIMERRING_MAX);
		}
	}
	assert(ntimerrings);
	rc = timer_allocrings();
	if (rc) {
		return rc;
	}
	for (i = 0; i < ntimerrings; ++i) {
		ring = timerrings[i];
		timerring_init(ring, seg_sizes[i]);
	}
	return 0;
}

void
timer_moddeinit()
{
	timer_freerings();
}

void
timer_init(struct timer *timer)
{
	timer->tm_data = 0;
}

int
timer_isrunning(struct timer *timer)
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
	struct timerring *ring;

	uint_fn = (uintptr_t)fn;
	assert(uint_fn != 0);
	assert((uint_fn & TIMERRING_ID_MASK) == 0);
	assert(expire <= TIMER_EXPIREMAX);
	timer_cancel(timer);
	dist = 0;
	for (ring_id = 0; ring_id < ntimerrings; ++ring_id) {
		ring = timerrings[ring_id];
		dist = expire >> ring->r_seg_shift;
		assert(dist >= 2);
		if (dist < TIMERRING_SIZE) {
			break;
		}
	}
	if (ring_id == ntimerrings) {
		ring_id = ntimerrings - 1;
		ring = timerrings[ring_id];
		dist = TIMERRING_SIZE - 1;
	}
	assert((ring_id & ~TIMERRING_ID_MASK) == 0);
	ring = timerrings[ring_id];
	pos = ring->r_pos + dist;
	seg = ring->r_segs + (pos & TIMERRING_MASK);
	ring->r_ntimers++;
	timer->tm_data = uint_fn|ring_id;
	DLIST_INSERT_HEAD(seg, timer, tm_list);
}

void
timer_cancel(struct timer *timer)
{
	int ring_id;
	struct timerring *ring;

	if (timer_isrunning(timer)) {
		ring_id = timerring_getid(timer);
		ring = timerrings[ring_id];
		ring->r_ntimers--;
		assert(ring->r_ntimers >= 0);
		DLIST_REMOVE(timer, tm_list);
		timer->tm_data = 0;
	}
}

void
timer_checktimo()
{
	int i;
	struct dlist q;
	struct timerring *ring;

	if (nanosec - timer_lasttime < 30 * NANOSECONDS_MILLISECOND) {
		return;
	}
	timer_lasttime = nanosec;
	dlist_init(&q);
	for (i = 0; i < ntimerrings; ++i) {
		ring = timerrings[i];
		timerring_checktimo(ring, &q);
	}
	timer_callq(&q);
}

static void
timerring_checktimo(struct timerring *ring, struct dlist *q)
{
	int i;
	uint64_t pos;
	struct timer *timer;
	struct dlist *seg;

	pos = ring->r_pos;
	ring->r_pos = (nanosec >> ring->r_seg_shift);
	assert(pos <= ring->r_pos);
	if (ring->r_ntimers == 0) {
		return;
	}
	for (i = 0; pos <= ring->r_pos && i < TIMERRING_SIZE; ++pos, ++i) {
		seg = ring->r_segs + (pos & TIMERRING_MASK);
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

static void
timer_callq(struct dlist *q)
{
	struct timer *timer;
	timer_f fn;

	while (!dlist_is_empty(q)) {
		timer = DLIST_FIRST(q, struct timer, tm_list);
		DLIST_REMOVE(timer, tm_list);
		fn = (timer_f)(timer->tm_data & ~TIMERRING_ID_MASK);
		timer->tm_data = 0;
		(*fn)(timer);
	}
}
