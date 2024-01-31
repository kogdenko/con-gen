#ifndef CONGEN_GLOBAL_H
#define CONGEN_GLOBAL_H

#include "subr.h"

extern int verbose;
extern int n_counters;

extern counter64_t if_ibytes;
extern counter64_t if_ipackets;
extern counter64_t if_obytes;
extern counter64_t if_opackets;
extern counter64_t if_imcasts;

extern uint64_t cg_tsc_mhz;

extern __thread struct cg_thread *current;
extern struct cg_dlist cg_threads_head;

#define CG_FOREACH_TASK(t) CG_DLIST_FOREACH(t, &cg_threads_head, t_list)

#endif
