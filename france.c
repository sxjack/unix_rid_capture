/* -*- tab-width: 2; mode: c; -*-
 * 
 * A program for capturing opendroneid / ASTM F3411 / ASD-STAN 4709-002 
 * WiFi beacon direct remote identification signals.
 *
 * This file contains the code to parse a French ID.
 *
 * Copyright (c) 2022 Steve Jack
 *
 * MIT licence
 *
 * Notes
 *
 *
 */

#pragma GCC diagnostic warning "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable" */

#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "rid_capture.h"

#define ID_SIZE (ODID_ID_SIZE + 1)

/*
 *
 */

void parse_id_france(uint8_t *mac,uint8_t *payload,struct UAV_RID *RID_data) {

  int            length, i, j, l, t, altitude_msl, height_agl, speed, heading;
  char           operator[ID_SIZE], serial[ID_SIZE];
  double         latitude, longitude, base_latitude, base_longitude;
  uint8_t       *v;
  time_t         secs;
  union {int32_t i32; uint32_t u32;}
                 uav_lat, uav_long, base_lat, base_long;
  union {int16_t i16; uint16_t u16;} 
                 alt, height;
  static int     pass = 0;
 
  /* */

  time(&secs);
                 
  operator[0]  = 0;
  serial[0]    = 0;

  uav_lat.u32   = 
  uav_long.u32  = 
  base_lat.u32  =
  base_long.u32 = 0;

  alt.u16       =
  height.u16    = 0;

  length = payload[1] + 2;

  /* Start the JSON output. */
  
  printf("{ \"mac\" : \"%02x:%02x:%02x:%02x:%02x:%02x\"",
         mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);

  /* */

  for (j = 6; j < length;) {

    t =  payload[j];
    l =  payload[j + 1];
    v = &payload[j + 2];

    switch (t) {

    case  1:

      if (v[0] != 1) {

        ;
      }

      break;

    case  2:

      for (i = 0; (i < (l - 6))&&(i < (ID_SIZE - 1)); ++i) {

        operator[i] = (char) v[i + 6];
      }

      operator[i] = 0;

      printf(", \"operator\" : \"%s\"",operator);
      break;

    case  3:

      for (i = 0; (i < l)&&(i < (ID_SIZE - 1)); ++i) {

        serial[i] = (char) v[i];
      }

      serial[i] = 0;

      printf(", \"uav id\" : \"%s\"",serial);
      break;

    case  4:

      for (i = 0; i < 4; ++i) {

        uav_lat.u32 <<= 8;
        uav_lat.u32  |= v[i];
      }

      break;

    case  5:

      for (i = 0; i < 4; ++i) {

        uav_long.u32 <<= 8;
        uav_long.u32  |= v[i];
      }

      break;

    case  6:

      alt.u16 = (((uint16_t) v[0]) << 8) | (uint16_t) v[1];
      break;

    case  7:

      height.u16 = (((uint16_t) v[0]) << 8) | (uint16_t) v[1];
      break;

    case  8:

      for (i = 0; i < 4; ++i) {

        base_lat.u32 <<= 8;
        base_lat.u32  |= v[i];
      }

      break;

    case  9:

      for (i = 0; i < 4; ++i) {

        base_long.u32 <<= 8;
        base_long.u32  |= v[i];
      }

      break;

    case 10:

      speed = v[0];   
      break;

    case 11:

      heading = (((uint16_t) v[0]) << 8) | (uint16_t) v[1];
      break;

    default:
    
      break;
    }

    j += l + 2;
  }

  latitude        = 1.0e-5 * (double) uav_lat.i32;
  longitude       = 1.0e-5 * (double) uav_long.i32;
  base_latitude   = 1.0e-5 * (double) base_lat.i32;
  base_longitude  = 1.0e-5 * (double) base_long.i32;

  altitude_msl    = alt.i16;
  height_agl      = height.i16;
  
  printf(", \"uav latitude\" : %11.6f, \"uav longitude\" : %11.6f",
         latitude,longitude);
  printf(", \"uav altitude\" : %d, \"uav heading\" : %d",
         altitude_msl,heading);
  printf(", \"uav speed\" : %d",speed);
  printf(", \"base latitude\" : %11.6f, \"base longitude\" : %11.6f",
         base_latitude,base_longitude);
  printf(", \"unix time\" : %lu",secs);

  printf(" }\n");

  /* */

  if (++pass == 1) {
    
    dump("french",payload,length);
  }

  return;
}

/*
 *
 */

