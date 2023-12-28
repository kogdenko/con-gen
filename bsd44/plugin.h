#ifndef CON_GEN_BSD44_PUGIN_H
#define CON_GEN_BSD44_PUGIN_H

#include <stdio.h>

void bsd_init(void);
void bsd_current_init(void);
void bsd_update(uint64_t tsc);
void bsd_flush(void);
void bsd_command(int command, FILE *out, int verbose);

#endif // CON_GEN_BSD44_PUGIN_H
