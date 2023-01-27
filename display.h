/* -*- tab-width: 2; mode: c; -*-
 * 
 * See display.c.
 *
 * Copyright (c) 2023 Steve Jack
 *
 * MIT licence
 *
 */

void  display_init(void);
void  display_end(void);

void  display_mac(int,uint8_t *);
void  display_identifier(int,const char *);
void  display_uav_loc(int,double,double,int,int);
void  display_timestamp(int,time_t);
void  display_note(int,const char *);
void  display_pass(int,const char *);
void  display_voltage(int,const float);

void  display_loop_diag(double,unsigned int);
