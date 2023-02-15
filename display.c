/* -*- tab-width: 2; mode: c; -*-
 * 
 * A program for capturing opendroneid / ASTM F3411 / ASD-STAN 4709-002 
 * WiFi beacon direct remote identification signals.
 *
 * A basic text display using ncurses.
 *
 * Copyright (c) 2022-2023 Steve Jack
 *
 * MIT licence
 *
 */

#pragma GCC diagnostic warning "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>

#include "rid_capture.h"

#if USE_CURSES
#include <curses.h>

#define NOTE_LEN  20

const int         MAC_COL  =   0, LAT_COL  =  38, LONG_COL =  50, ALT_COL = 62,
                  OP_COL   =  18, TS_L_COL =  70, TS_S_COL =  76,
                  PASS_COL = 115, NOTE_COL =  95, VOLT_COL = 120, 
                  NOTE_ROW =  22;
WINDOW           *window = NULL;

static int        nrows = 25, ncols = 132;
#endif

/*
 *
 */

void display_init() {

#if USE_CURSES

  if (window = initscr()) {

    resizeterm(nrows,ncols);
    clear();
    curs_set(0);
    mvaddstr( 0,OP_COL   + 1,"Identifier");
    mvaddstr( 0,LAT_COL  + 1,"Lat.");
    mvaddstr( 0,LONG_COL + 1,"Long.");
    mvaddstr( 0,ALT_COL  + 1,"Alt.");
    mvaddstr( 0,TS_L_COL + 2,"Timestamps");
    mvaddstr(NOTE_ROW + 2, 0,"^C to end program");

    refresh();
  }

#endif

  return;
}

/*
 *
 */

void display_end() {

#if USE_CURSES

  if (window) {

    endwin();
    window = NULL;
  }

#endif

  return;
}

/*
 *
 */

void display_mac(int row,uint8_t *mac) {

#if USE_CURSES

  char text[32];

  if (window) {

    sprintf(text,"%02x:%02x:%02x:%02x:%02x:%02x ",
            mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
    mvaddstr(row,MAC_COL,text);

    refresh();
  }

#endif

  return;
}

/*
 *
 */

void display_identifier(int row,const char *ident) {

#if USE_CURSES

  char text[32];

  if (window) {

    sprintf(text,"%-20s ",ident);
    mvaddstr(row,OP_COL,text);

    refresh();
  }

#endif

  return;
}

/*
 *
 */

void display_uav_loc(int row,double latitude,double longitude,int altitude,int hsecs) {

#if USE_CURSES

  char text[32];

  if (window) {

    sprintf(text,"%11.6f ",latitude);
    mvaddstr(row,LAT_COL,text);
    sprintf(text,"%11.6f ",longitude);
    mvaddstr(row,LONG_COL,text);
    sprintf(text,"%5d ",altitude);
    mvaddstr(row,ALT_COL,text);

    if (hsecs < 3600) {
      sprintf(text,"%02d:%02d ",hsecs / 60,hsecs % 60);
      mvaddstr(row,TS_L_COL,text);
    }

    refresh();
  }

#endif

  return;
}

/*
 *
 */

void display_timestamp(int row,time_t secs) {

#if USE_CURSES

  char       text[32];
  struct tm *timestamp;

  timestamp = gmtime(&secs);
 
  if (window) {

    sprintf(text,"%02d-%02d-%02d %02d:%02d:%02d ",
            timestamp->tm_year % 100,timestamp->tm_mon + 1,timestamp->tm_mday,
            timestamp->tm_hour,      timestamp->tm_min,    timestamp->tm_sec);
    mvaddstr(row,TS_S_COL,text);

    refresh();
  }

#endif

  return;
}

/*
 *
 */

void display_note(int row,const char *note) {

#if USE_CURSES

  int  i;
  char text[NOTE_LEN + 2];

  memset(text,0,sizeof(text));
  strncpy(text,note,NOTE_LEN);

  for (i = strlen(text); i < NOTE_LEN; ++i) {
    text[i] = ' ';
  }

  if (window) {

    if (row > 0) {
      mvaddstr(row,NOTE_COL,text);
    } else {
      mvaddstr(NOTE_ROW,LONG_COL,text);
    }

    refresh();
  }

#endif

  return;
}

/*
 *
 */

void display_pass(int row,const char *pass) {

#if USE_CURSES

  if (window) {

    mvaddstr(row,PASS_COL,pass);

    refresh();
  }

#endif

  return;
}

/*
 *
 */

void display_voltage(int row,const float volts) {

#if USE_CURSES

  char text[32];

  if (window) {

    sprintf(text,"%4.2f ",volts);
    if (row > 0) {
      mvaddstr(row,VOLT_COL,text);
    } else {
      mvaddstr(NOTE_ROW,VOLT_COL,text);
    }

    refresh();
  }

#endif

  return;
}

/*
 *
 */

void display_loop_diag(double loop_us,unsigned int packets_1s) {

#if USE_CURSES

  char text[32];

  sprintf(text," %7.0f us %4u msg/s",
          loop_us,packets_1s);

  if (window) {

    mvaddstr(NOTE_ROW,0,text);

    refresh();
  }

#endif

  return;
}

/*
 *
 */

