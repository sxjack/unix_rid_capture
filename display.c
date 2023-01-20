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

const int         MAC_COL = 0, LAT_COL = 38, LONG_COL = 50, ALT_COL = 62,
                  OP_COL = 18, TS_L_COL = 70, TS_S_COL = 76,
                  NOTE_COL = 100, NOTE_ROW = 17;
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
    mvaddstr( 0,ALT_COL  + 1, "Alt.");
    mvaddstr( 0,TS_L_COL + 2, "Timestamps");
    mvaddstr(NOTE_ROW,0,"^C to end program");
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

  secs      += ID_OD_AUTH_DATUM;
  timestamp  = gmtime(&secs);
 
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

void display_note(int row,const char *note) {

#if USE_CURSES

  if (window) {
    if (row > 0) {
      mvaddstr(row,NOTE_COL,note);
    } else {
      mvaddstr(NOTE_ROW,LONG_COL,note);
    }
    refresh();
  }

#endif

  return;
}

/*
 *
 */

/*
 *
 */

