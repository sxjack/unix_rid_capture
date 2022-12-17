/* -*- tab-width: 2; mode: c; -*-
 * 
 *
 *
 * Copyright (c) 2022 Steve Jack
 *
 * MIT licence
 *
 */

#include <stdint.h>
#include <sys/types.h>

#include "opendroneid.h"

#define MAX_UAVS    20
#define ASTERIX      0
#define VERIFY       0
#define NRF_SNIFFER  0
#define ID_FRANCE    1
#define FA_EXPORT    1

#define ID_OD_AUTH_DATUM  1546300800LU

struct UAV_RID {u_char        mac[6];
                unsigned int  packets;
                time_t        last_rx, last_retx;
                ODID_UAS_Data odid_data;
#if VERIFY
                int           auth_length;
                uint8_t       auth_buffer[ODID_AUTH_MAX_PAGES * ODID_AUTH_PAGE_NONZERO_DATA_SIZE + 1];
#endif
                int           rssi;
};

void  parse_odid(u_char *,u_char *,int,int);
int   mac_index(uint8_t *,struct UAV_RID *);
void  dump(char *,uint8_t *,int);
char *printable_text(uint8_t *,int);
int   write_json(char *);

pid_t start_nrf_sniffer(const char *,int *);
void  parse_nrf_sniffer(uint8_t *,int);
void  stop_nrf_sniffer(void);

void  parse_id_france(uint8_t *,uint8_t *,struct UAV_RID *);

int   init_crypto(uint8_t *,int,uint8_t *,int,FILE *);
void  parse_auth(ODID_UAS_Data *,ODID_MessagePack_encoded *,struct UAV_RID *);
void  close_crypto(void);

int   fa_export(time_t,struct UAV_RID *);

void  asterix_init(void);
void  asterix_transmit(struct UAV_RID *);
void  asterix_end(void);

/*
 *
 */
