#ifndef CON_GEN__GLOBAL_H
#define CON_GEN__GLOBAL_H

#include "subr.h"

extern int verbose;
extern int n_counters;

extern counter64_t if_ibytes;
extern counter64_t if_ipackets;
extern counter64_t if_obytes;
extern counter64_t if_opackets;
extern counter64_t if_imcasts;

extern uint64_t cg_tsc_mhz;

extern int n_threads;
extern __thread struct thread *current;
extern struct thread threads[N_THREADS_MAX];



#endif
