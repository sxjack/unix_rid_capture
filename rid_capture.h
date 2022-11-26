/* -*- tab-width: 2; mode: c; -*-
 * 
 *
 *
 * Copyright (c) 2022 Steve Jack
 *
 * MIT licence
 *
 */

#include "opendroneid.h"

#define MAX_UAVS 20
#define ASTERIX   0

#define ID_OD_AUTH_DATUM  1546300800LU

struct UAV_RID {u_char        mac[6];
                time_t        last_rx, last_retx;
                ODID_UAS_Data odid_data;
};

void asterix_init(void);
void asterix_transmit(struct UAV_RID *);
void asterix_end(void);

/*
 *
 */
