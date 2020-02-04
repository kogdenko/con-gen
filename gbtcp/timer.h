/* GPL2 license */

#ifndef GBTCP_TIMER_H
#define GBTCP_TIMER_H

#include "list.h"
#include "../bsd44/types.h"

#define TIMERRING_SIZE 4096llu
#define TIMERRING_MASK (TIMERRING_SIZE - 1llu)
#define TIMERRING_ID_SHIFT 3
#define TIMER_EXPIREMAX (5 * 60 * 60 * TM_1SEC) // 5 Hours

struct timer {
	struct dllist tm_list;
	uintptr_t tm_data;
};

typedef void (*timer_f)(struct timer *);

int timer_modinit();

void timer_moddeinit();

void timer_checktimo();

void timer_init(struct timer *timer);

int timer_isrunning(struct timer *timer);

void timer_set(struct timer *timer, uint64_t expire, timer_f fn);

void timer_cancel(struct timer *timer);

#endif /* GBTCP_TIMER_H */
