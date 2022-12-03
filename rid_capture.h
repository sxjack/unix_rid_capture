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

#define MAX_UAVS  20
#define ASTERIX    0
#define VERIFY     0
#define ID_FRANCE  1

#define ID_OD_AUTH_DATUM  1546300800LU

struct UAV_RID {u_char        mac[6];
                unsigned int  packets;
                time_t        last_rx, last_retx;
                ODID_UAS_Data odid_data;
};

void dump(char *,uint8_t *,int);

void parse_id_france(uint8_t *,uint8_t *,struct UAV_RID *);

int  init_crypto(uint8_t *,int,uint8_t *,int,FILE *);
void parse_auth(ODID_UAS_Data *,ODID_MessagePack_encoded *);
void close_crypto(void);

void asterix_init(void);
void asterix_transmit(struct UAV_RID *);
void asterix_end(void);

/*
 *
 */
