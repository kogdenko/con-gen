// gpl2 license
#ifndef GBTCP_TCP_H
#define GBTCP_TCP_H

#include "../global.h"
#include "timer.h"

struct tcp_param {
	be32_t laddr;
	be32_t faddr;
	be16_t lport;
	be16_t fport;
};

#endif
