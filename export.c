/* -*- tab-width: 2; mode: c; -*-
 * 
 * A program for capturing opendroneid / ASTM F3411 / ASD-STAN 4709-002 
 * WiFi beacon direct remote identification signals.
 *
 * This file has code to export the data. It should be easy to add other formats.
 *
 * Copyright (c) 2022 Steve Jack
 *
 * MIT licence
 *
 * fa_export()
 *
 * Writes an aircraft.json file in FlightAware format in a data subdirectory. 
 * If your machine is a webserver and has the FlightAware package installed,
 * link this directory to the data directory that the FA web application uses.
 * (Don't do this if you are actually using the FA package to collect information
 * transmitted on 1090 MHz.)
 *
 * https://www.adsbexchange.com/ads-b-data-field-explanations/
 *
 * To do:
 *
 * Check units.
 * I don't know how FA does the tracks, it doesn't seem to use the history files. 
 * It doesn't seem worth bothering with the history files.
 *
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <pwd.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "rid_capture.h"

#define FA_HISTORY    0
#define FA_RECEIVER   0
#define SQUAWK     7000 // VFR, 7000 in Europe, 1200 in North America.

/*
 *
 */

extern uid_t        nobody;
extern gid_t        nogroup;
extern const mode_t file_mode, dir_mode;

#if FA_EXPORT

static char    fa_dir[] = "data";
#if FA_RECEIVER || FA_HISTORY
static double  base_lat = 52.0 + (46.0 / 60.0) + (49.89 / 3600.0), // BMFA
               base_lon =  0.0 - (42.0 / 60.0) - (26.26 / 3600.0); // Buckminster

static void    write_receiver(long int);
#endif

#endif

/*
 *
 */

#if FA_EXPORT

int fa_export(time_t secs,struct UAV_RID *RID_data) {

  int                uav, j, alt, speed_h, speed_v, heading, seen, rssi = -50;
  char               filename[128];
  double             mach;
  unsigned long int  total;
  FILE              *output;
  static char        first_call = 1;
#if FA_HISTORY
  static long int    next_history = 0;
  static time_t      last_history = 0;
#endif

  if (first_call) {

    first_call = 0;

    mkdir(fa_dir,dir_mode);
    chmod(fa_dir,dir_mode);
    chown(fa_dir,nobody,nogroup);
#if FA_RECEIVER
    write_receiver(0);
#endif
  }

  sprintf(filename,"%s/aircraft.json",fa_dir);

#if FA_HISTORY
  int  old_hist = 0;
  char filename2[128];

  if ((secs - last_history) > 1) {

    last_history = secs;

    if ((old_hist = (next_history - FA_HISTORY)) >= 0)  {
    
      sprintf(filename2,"%s/history_%d.json",fa_dir,old_hist);
      unlink(filename2);
    }

    sprintf(filename2,"%s/history_%ld.json",fa_dir,next_history);
    rename(filename,filename2);

    write_receiver(next_history);

    ++next_history;
  }
#endif

  if (output = fopen(filename,"w")) {

    chmod(filename,file_mode);

    if (nobody) {
      chown(filename,nobody,nogroup);
    }

    for (uav = 0, total = 0; uav < MAX_UAVS; ++uav) {
      total += RID_data[uav].packets;
    }

    fprintf(output,"{ \"now\" : %lu,\n",secs);
    fprintf(output,"  \"messages\" : %lu,\n",total);    
    fputs("  \"aircraft\" : [\n",output);

    for (uav = 0, j = 0; uav < MAX_UAVS; ++uav) {

      if ((RID_data[uav].mac[0])&&
          (RID_data[uav].odid_data.System.Timestamp)&&
          (RID_data[uav].odid_data.Location.Latitude)&&
          (RID_data[uav].odid_data.Location.Longitude)) {

        if (j++) {
          fputs(",\n",output);
        }

        fputs("    {",output);

#if 1 // Use unused hex codes.
        fprintf(output, " \"hex\":\"%06x\"",uav + 1);
#else // Use the MAC.
        uint8_t * mac = RID_data[uav].mac;

        fprintf(output, " \"hex\":\"%02x%02x%02x%02x%02x%02x\"",
                mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
#endif
        fprintf(output,", \"flight\":\"G-UAV%d\"",uav + 1);
        fprintf(output,", \"squawk\":\"%04d\"",SQUAWK);

        alt     = (int) (RID_data[uav].odid_data.Location.AltitudeGeo * 3.28084);          /* m   -> ft */
        mach    = RID_data[uav].odid_data.Location.SpeedHorizontal / 340.0;
        seen    = (int) (secs - RID_data[uav].last_rx);
        rssi    = (RID_data[uav].rssi) ? RID_data[uav].rssi: -50;

        if ((heading = (int) (RID_data[uav].odid_data.Location.Direction)) > 180) {
          heading -= 360;
        }
        
        speed_h = (RID_data[uav].odid_data.Location.SpeedHorizontal < (float) INV_SPEED_H) ?
                  (int) (RID_data[uav].odid_data.Location.SpeedHorizontal * 1.94384):      /* m/s -> knots */
                  0;
        speed_v = (RID_data[uav].odid_data.Location.SpeedVertical < (float) INV_SPEED_V) ?
                  (int) (RID_data[uav].odid_data.Location.SpeedVertical * 3.28084 * 60.0): /* m/s -> ft/m */
                  0;

        if (RID_data[uav].odid_data.Location.AltitudeBaro > INV_ALT) {
  
          fprintf(output,", \"alt_baro\":%d",
                  (int) (RID_data[uav].odid_data.Location.AltitudeBaro * 3.28084));
        }

        fprintf(output,", \"alt_geom\":%d, \"nav_altitude\":%d",alt,alt);
        fprintf(output,", \"geom_rate\":%d",speed_v);
        fprintf(output,", \"gs\":%d, \"ias\":%d, \"tas\":%d, \"mach\":%.3f",
                speed_h,speed_h,speed_h,mach);
        fprintf(output,", \"track\":%d, \"nav_heading\":%d",heading,heading);
        fprintf(output,", \"lat\":%.6f, \"lon\":%.6f",
                RID_data[uav].odid_data.Location.Latitude,
                RID_data[uav].odid_data.Location.Longitude);

        fputs(", \"category\":\"B6\"",output);
        fputs(", \"version\":2, \"nic\":8, \"nic_baro\":10, \"nac_p\":9, \"nac_v\":0 ",output);
        fputs(", \"sil\":0, \"rc\":30",output);

        fprintf(output,", \"messages\":%u",RID_data[uav].packets);
        fprintf(output,", \"seen_pos\":%d, \"seen\":%d",seen,seen);

         /* If we don't provide an RSSI, FA doesn't think that we are providing a position. */
        fprintf(output,", \"rssi\":%d",rssi);

        fputs(" }",output);
      }
    }

    fputs("\n  ]\n}\n",output);

    fclose(output);

  } else {

    fprintf(stderr,"%s(): Unable to open \'%s\', %d\n",__func__,filename,errno);
  }
  
  return 0;
}

#endif

/*
 *
 */

#if FA_RECEIVER || FA_HISTORY

void write_receiver(long int history) {

  char  filename2[128];
  FILE *output;
  
  sprintf(filename2,"%s/receiver.json",fa_dir);

  if (output = fopen(filename2,"w")) {

    chmod(filename2,file_mode);
    chown(filename2,nobody,nogroup);

    fprintf(output,"{ \"version\" : \"\", \"refresh\" : 1000, \"history\" : %ld, ",
            history);
    fprintf(output," \"lat\" : %.4f, \"lon\" : %.4f }\n",
            base_lat,base_lon);

    fclose(output);
  }

  return;
}

#endif

/*
 *
 */

