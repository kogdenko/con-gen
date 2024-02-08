// gpl2 license
#ifndef CON_GEN__GBTCP__TIMER_H
#define CON_GEN__GBTCP__TIMER_H

#include <inttypes.h>
#include "list.h"

#define CG_TIMER_RING_SIZE 4096llu
#define CG_TIMER_RING_MASK (CG_TIMER_RING_SIZE - 1llu)
#define CG_TIMER_EXPIRE_MAX (5 * 60 * 60 * NANOSECONDS_SECOND) // 5 Hours

struct timer;
struct cg_task;

typedef void (*timer_f)(struct cg_task *t, struct timer *);

struct timer {
	struct dlist tm_list;
	timer_f tm_fn;	
	uint8_t tm_ring_id;
};

void cg_init_timers(struct cg_task *);
void cg_deinit_timers(struct cg_task *);

void cg_check_timers(struct cg_task *t);
void timer_init(struct timer *);
int timer_is_running(struct timer *);
void timer_set(struct cg_task *, struct timer *, uint64_t, timer_f);
void timer_cancel(struct cg_task *, struct timer *);

#endif // CON_GEN__GBTCP__TIMER_H
