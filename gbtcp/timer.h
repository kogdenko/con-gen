// gpl2 license
#ifndef CON_GEN__GBTCP__TIMER_H
#define CON_GEN__GBTCP__TIMER_H

#include "../subr.h"
#include "list.h"

#define TIMER_RING_SIZE 4096llu
#define TIMER_RING_MASK (TIMER_RING_SIZE - 1llu)
#define TIMER_RING_ID_SHIFT 3
#define TIMER_EXPIRE_MAX (5 * 60 * 60 * NANOSECONDS_SECOND) // 5 Hours

struct timer {
	struct dlist tm_list;
	uintptr_t tm_data;
};

typedef void (*timer_f)(struct timer *);

int init_timers(void);
void deinit_timers(void);

void check_timers(void);
void timer_init(struct timer *);
int timer_is_running(struct timer *);
void timer_set(struct timer *, uint64_t, timer_f);
void timer_cancel(struct timer *);

#endif // CON_GEN__GBTCP__TIMER_H
