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

#pragma GCC diagnostic warning "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <pwd.h>
#include <time.h>

#include <sys/stat.h>
#include <sys/types.h>

#include "rid_capture.h"

/*
 *
 */

static const char   title[] = "RID Capture";

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
                (i) ? ",\n": "",i,mac);
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

      a = RID_data[i].odid_data.SelfID.Desc;

      if ((log)&&(a[0])) {
        fprintf(log,"    \"self id\"   : \"%s\",\n",a);
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
        fprintf(log,"  }");
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
    fputs("\n}\n",log);
    fclose(log);
  }

  chmod(filename,file_mode);

  return;
}

/*
 *
 */

int www_export(char *dir,time_t secs,struct UAV_RID *RID_data) {

  int         i, hsecs;
  char        filename[128], *a, *b;
  FILE       *page;
  time_t      ts;
  struct tm  *gmt, *acquired;
  const char *header1[] = {"<html>\n",
                           "<head>",
                           "<meta http-equiv=\"Refresh\" content=\"1\"/>",
                           "" },
             *header2[] = {"<link rel=\"stylesheet\" type=\"text/css\" href=\"default.css\"/>",
                           "</head>\n",
                           "<body>",
                           "<table border=\"0\" cellpadding=\"3\" style=\"margin-left: 10pt\">",
                           "" },
             *table1 =     "<tr align=\"center\"><td><b>Acquired</b></td>"
                           "<td><b>Operator</b></td><td><b>UAV</b></td>"
                           "<td><b>Latitude</b></td><td><b>Longitude</b></td>"
                           "<td><b>Altitude</br>(m msl)</b></td></tr>",
             *footer[]  = {"</table>",
                           "</body>\n",
                           "</html>",
                           "" };

  gmt = gmtime(&secs);

  sprintf(filename,"%s/index.html",dir);
  
  if (page = fopen(filename,"w")) {

    for (i = 0; (i < 16)&&(*header1[i]); ++i) {
      fprintf(page,"%s\n",header1[i]);
    }

    fprintf(page,"<title>%s</title>\n",title);

    for (i = 0; (i < 16)&&(*header2[i]); ++i) {
      fprintf(page,"%s\n",header2[i]);
    }

    fprintf(page,"<tr align=\"center\"><td>%02d:%02d:%02d</td></tr>\n",
            gmt->tm_hour,gmt->tm_min,gmt->tm_sec);

    fprintf(page,"%s\n",table1);

    for (i = 0; i < MAX_UAVS; ++i) {

      if (RID_data[i].mac[0]) {

        fputs("<tr align=\"center\">",page);

        hsecs    = (int) RID_data[i].odid_data.Location.TimeStamp;
        ts       = (RID_data[i].odid_data.System.Timestamp) ? (time_t) RID_data[i].odid_data.System.Timestamp:
                                                              RID_data[i].last_rx;
        acquired = gmtime(&ts);
#if 0
        if ((hsecs > -1)&&(hsecs < 3600)) {
          fprintf(page,"<td>%02d:%02d</td>",hsecs / 60,hsecs % 60);
        } else {
          fputs("<td></td>",page);
        }
#endif
#if 1
        fprintf(page,"<td>%02d:%02d:%02d</td>",
                acquired->tm_hour,acquired->tm_min,acquired->tm_sec);
#endif
        a = RID_data[i].odid_data.OperatorID.OperatorId;
        b = RID_data[i].basic_caa_reg.UASID;
        fprintf(page,"<td>%s</td>",(*a) ? a: ((*b) ? b: "-"));

        a = RID_data[i].basic_serial.UASID;
        b = RID_data[i].odid_data.BasicID[0].UASID;
        fprintf(page,"<td>%s</td>",(*a) ? a: ((*b) ? b: "-"));

        fprintf(page,"<td>%.6f</td>",RID_data[i].odid_data.Location.Latitude);
        fprintf(page,"<td>%.6f</td>",RID_data[i].odid_data.Location.Longitude);
        fprintf(page,"<td>%d</td>",(int) RID_data[i].odid_data.Location.AltitudeGeo);

        fputs("</tr>\n",page);
      }
    }

    for (i = 0; (i < 16)&&(*footer[i]); ++i) {
      fprintf(page,"%s\n",footer[i]);
    }

    fprintf(page,"\n<!-- Build date: %s -->\n",__DATE__);

    fclose(page);

    chmod(filename,file_mode);
    chown(filename,nobody,nogroup);
  }
  
  return 0;
}

/*
 *
 */
