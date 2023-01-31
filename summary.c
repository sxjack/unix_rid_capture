/* -*- tab-width: 2; mode: c; -*-
 * 
 * A program for capturing opendroneid / ASTM F3411 / ASD-STAN 4709-002 
 * WiFi and Bluetooth direct remote identification signals.
 *
 * This file has the code to produce the summary report when the program ends.
 *
 * Copyright (c) 2023 Steve Jack
 *
 * MIT licence
 *
 * Notes
 *
 * If we make the log dir user setable in rid_capture.c, we wil have to revisit filename below.
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <pwd.h>

#include <sys/stat.h>
#include <sys/types.h>

#include "rid_capture.h"

/*
 *
 */

extern uid_t        nobody;
extern gid_t        nogroup;
extern const mode_t file_mode, dir_mode;

/*
 *
 */

void print_summary(char *dir,FILE *stderr2,struct UAV_RID *RID_data,int records) {

  int     i, j, m_ew, m_ns;
  char   *uav_id, *operator, *a;
  char    filename[48], mac[32];
  double  m_deg_lat, m_deg_long, latitude, longitude;
  FILE   *log;

  sprintf(filename,"%s/summary.txt",dir);

  if (log = fopen(filename,"w")) {
    fputs("{\n",log);
  }

  if (stderr2) {
    fprintf(stderr2,"\n%-20s %-20s %-7s %-10s  %-10s  %-10s \n",
            "UAV","operator","packets","last rx",
            "latitude","longitude");
  }

  for (i = 0; i < records; ++i) {

    if (RID_data[i].mac[0]) {

      operator = NULL;
      uav_id   = mac;

      sprintf(mac,"%02x:%02x:%02x:%02x:%02x:%02x",
              (unsigned int) RID_data[i].mac[0],(unsigned int) RID_data[i].mac[1],
              (unsigned int) RID_data[i].mac[2],(unsigned int) RID_data[i].mac[3],
              (unsigned int) RID_data[i].mac[4],(unsigned int) RID_data[i].mac[5]);

      if (log) {
        fprintf(log,"%s  \"uav%d\" : {\n    \"mac\"       : \"%s\",\n",
                (i)? "\n  },\n": "",i,mac);
      }

      a = RID_data[i].odid_data.OperatorID.OperatorId;
        
      if ((log)&&(a[0])) {
        operator = a;
        fprintf(log,"    \"operator\"  : \"%s\",\n",a);
      }

      a = RID_data[i].basic_serial.UASID;

      if ((log)&&(a[0])) {
        uav_id = a;
        fprintf(log,"    \"serial\"    : \"%s\",\n",a);
      }

      a = RID_data[i].basic_caa_reg.UASID;

      if ((log)&&(a[0])) {
        if (!operator) {
          operator = a;
        }
        fprintf(log,"    \"CAA reg\"   : \"%s\",\n",a);
      }

      for (j = 0; j < ODID_BASIC_ID_MAX_MESSAGES; ++j) {

        a = RID_data[i].odid_data.BasicID[j].UASID;

        if ((log)&&(a[0])) {
          fprintf(log,"    \"basic%d\"    : \"%s\",\n",j,a);
        }
      }
    
      latitude  = RID_data[i].odid_data.Location.Latitude;
      longitude = RID_data[i].odid_data.Location.Longitude;

      calc_m_per_deg(latitude,&m_deg_lat,&m_deg_long);

      m_ew = (int) (m_deg_long * (RID_data[i].max_long - RID_data[i].min_long));
      m_ns = (int) (m_deg_lat  * (RID_data[i].max_lat  - RID_data[i].min_lat));

      if (log) {
        fprintf(log,"    \"latitude\"  : { \"min\" : %11.6f, \"max\" : %11.6f, \"ew\" : %3d },\n",
                RID_data[i].min_lat,RID_data[i].max_lat,m_ew);
        fprintf(log,"    \"longitude\" : { \"min\" : %11.6f, \"max\" : %11.6f, \"ns\" : %3d },\n",
                RID_data[i].min_long,RID_data[i].max_long,m_ns);
        fprintf(log,"    \"altitude\"  : { \"min\" :%7.1f,      \"max\" :%7.1f }\n",
                RID_data[i].min_alt,RID_data[i].max_alt);
      }

      if (stderr2) {
        fprintf(stderr2,"%-20s %-20s %7u %10lu %11.6f %11.6f ",
                (uav_id) ? uav_id: "",(operator) ? operator: "",
                RID_data[i].packets,RID_data[i].last_rx,
                latitude,longitude);
#if VERIFY
        fputs(printable_text(RID_data[i].auth_buffer,RID_data[i].auth_length),stderr2);
#endif
        fputs("\n",stderr2);
      }
    }
  }

  if (log) {
    fputs("  }\n}\n",log);
    fclose(log);
  }

  chmod(filename,file_mode);

  return;
}

/*
 *
 */

