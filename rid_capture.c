/* -*- tab-width: 2; mode: c; -*-
 * 
 * A program for capturing opendroneid / ASTM F3411 / ASD-STAN 4709-002 
 * WiFi beacon direct remote identification signals.
 *
 * Copyright (c) 2022 Steve Jack
 *
 * MIT licence
 *
 * Notes
 *
 * Developed on -
 * 1) an NC10 running Debian using its native WiFi hardware and a ZyXEL AC1200 (RTL2812AU),
 * 2) a Raspberry Pi running Raspbian using a ZyXEL AC1200.
 *
 * Don't compile with -std=c99, libpcap doesn't like it.
 *
 * Pi
 * RTL8812AU driver 88XXAU, trying to set monitor mode via libpcap causes an error.
 *
 *
 * To Do
 *
 * Fully setup the WiFi device.
 *
 */

#define DEBUG_FILE 1

#pragma GCC diagnostic warning "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"

#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#include <sys/utsname.h>
#include <pcap/pcap.h>

#include "rid_capture.h"

#define BUFFER_SIZE 2048

static FILE              *debug_file = NULL;
static const char        *default_key = "0123456789abcdef", *default_iv = "nopqrs",
                         *debug_filename = "debug.txt",
                          fwd_slash = 0x5c;
static volatile int       end_program     = 0, header_type = 0;
static volatile uint32_t  rx_packets = 0, odid_packets = 0;
static const char        *filter_text     = "ether broadcast or ether dst 51:6f:9a:01:00:00 ",
                          device_pi[10]   = "wlan1",
                          device_i686[10] = "wlp5s0b1";
static struct UAV_RID     RID_data[MAX_UAVS];

void list_devices(char *);
void packet_handler(u_char *,const struct pcap_pkthdr *,const u_char *);
void parse_odid(u_char *,u_char *,int);
void signal_handler(int);

/*
 *
 */

int main(int argc,char *argv[]) {

  int                 i, set_monitor = 1, man_dev = 0, key_len, iv_len;
  char               *arg, errbuf[PCAP_ERRBUF_SIZE], *device_name;
  uint8_t            *key = NULL, *iv = NULL;
  u_char              message[16];
  time_t              secs;
  pcap_t             *session = NULL;
  bpf_u_int32         network = 0;
  struct bpf_program  filter;
  struct utsname      sys_uname;
  static time_t       last_debug = 0;

  key = (uint8_t *) default_key;
  iv  = (uint8_t *) default_iv;

#if DEBUG_FILE

  debug_file = fopen(debug_filename,"w");
  
#endif
  
  uname(&sys_uname);
  
  if (!strncmp("i686",sys_uname.machine,4)) {
  
    device_name = (char *) device_i686;

  } else {

    device_name = (char *) device_pi;
  }

  fputs(argv[0],stderr);
  
  for (i = 1; i < argc; ++i) {

    fprintf(stderr, " %s",arg = argv[i]);
  
    if (*argv[i] == '-') {

      switch (arg[1]) {

      case 'x':

        set_monitor = 0;
        break;
        
      default:
        break;
      }

    } else {

      man_dev     = 1;
      device_name = arg;
    }
  }

  if (!man_dev) {

    fprintf(stderr," %s",device_name);
  }
  
  fprintf(stderr,"\n%s %s\n",sys_uname.sysname,sys_uname.machine);

  signal(SIGINT,signal_handler);

  memset(&RID_data,0,sizeof(RID_data));
  memset(message,0,sizeof(message));

#if ASTERIX

  asterix_init();
  
#endif

  key_len = strlen((char *) key);
  iv_len  = strlen((char *) iv);

#if VERIFY

  if (i = init_crypto(key,key_len,iv,iv_len,debug_file)) {

    exit(i);
  }
  
#endif
  
  /* 
   */

  if (!(session = pcap_create(device_name,errbuf))) {

    fprintf(stderr,"pcap_open_live(): %s\n",errbuf);

    list_devices(errbuf);

    exit(1);
  }

#if 0

  /* This doesn't seem to work. 
   */
  
  int status;

  if ((status = pcap_can_set_rfmon(session)) != 0) {

    fprintf(stderr,"pcap_can_set_rfmon(): cannot set rfmon (%d), aborting\n",status);

    pcap_close(session);
    
    exit(1);
  }

#endif

  if (set_monitor) {
  
    if (pcap_set_rfmon(session,1) != 0) {

      fprintf(stderr,"pcap_set_rfmon():  %s\n",pcap_geterr(session));
    }
  }

#if 0

  bpf_u_int32 netmask = 0;

  if (pcap_lookupnet(device_name,&network,&netmask,errbuf) < 0) {

    fprintf(stderr,"pcap_lookupnet(%s): %s\n",device_name,errbuf);
  }

#endif

  if (pcap_activate(session)) {

    fprintf(stderr,"pcap_activate():  %s\n",pcap_geterr(session));
    fputs("This error may mean that your wifi hardware is not capable of being put into monitor mode.\n",stderr);

    if (set_monitor) {

      fputs("Try setting monitor mode using iw and using the -x option to this program.\n",stderr);
     }

    list_devices(errbuf);

    exit(1);
  }

  if ((header_type = pcap_datalink(session)) != DLT_IEEE802_11_RADIO) {

    fprintf(stderr,"pcap_datalink(): Not tested on this header type. ^C now to abort. : %d\n",
            header_type);
  }
  
  if (pcap_compile(session,&filter,filter_text,0,network)) {

    fprintf(stderr,"pcap_compile(): \"%s\" : %s\n",filter_text,pcap_geterr(session));
  }

  if (pcap_setfilter(session,&filter)) {

    fprintf(stderr,"pcap_setfilter():  %s\n",pcap_geterr(session));
  }

  /* 
   */

  time(&secs);
  last_debug = secs;

  if (header_type != DLT_IEEE802_11_RADIO) {

      do {

        time(&secs);

      } while (secs < (last_debug + 2));
  }

  fprintf(stderr,"Capturing (type %d)\n",header_type);

  while (!end_program) {
    
    pcap_loop(session,1,packet_handler,message);

    time(&secs);

    if ((secs - last_debug) > 9) {

      printf("{ \"debug\" : \"rx packets %u (%u)\" }\n",rx_packets,odid_packets);

      last_debug = secs;
    }

#if 0
    if ((odid_packets % 20) == 19) {

      fputc('.',stderr);
      fflush(stderr);
    }
#endif
    
#if ASTERIX
    static time_t last_asterix = 0;

    if ((secs - last_asterix) > 4) {

      asterix_transmit(RID_data);
      
      last_asterix = secs;
    }
#endif
  }

  /* 
   */

#if VERIFY

  close_crypto();

#endif

  pcap_close(session);

  if (RID_data[0].mac[0]) {

#if ASTERIX
    fprintf(stderr,"\n\n%-17s packets %-10s %-10s operator\n","MAC","last rx","last retx");
#else
    fprintf(stderr,"\n\n%-17s packets %-10s operator\n","MAC","last rx");
#endif

    for (int i = 0; i < MAX_UAVS; ++i) {

      if (RID_data[i].mac[0]) {

        fprintf(stderr,"%02x:%02x:%02x:%02x:%02x:%02x %7u ",
                RID_data[i].mac[0],RID_data[i].mac[1],RID_data[i].mac[2],
                RID_data[i].mac[3],RID_data[i].mac[4],RID_data[i].mac[5],
                RID_data[i].packets);
#if ASTERIX
        fprintf(stderr,"%10lu %10lu %s\n",
                RID_data[i].last_rx,RID_data[i].last_retx,
                RID_data[i].odid_data.OperatorID.OperatorId);
#else
        fprintf(stderr,"%10lu %s\n",
                RID_data[i].last_rx,
                RID_data[i].odid_data.OperatorID.OperatorId);
#endif
      }
    }
#if ID_FRANCE
    fprintf(stderr,"\n(Summary excludes French IDs.)\n");
#endif
  }

  if (debug_file) {

    fclose(debug_file);
  }
  
  exit(0);
}

/*
 *
 */

void list_devices(char *errbuf) {

  int        i;
  pcap_if_t *devices, *dev;

  fprintf(stderr,"Available devices\n");
  
  if (pcap_findalldevs(&devices,errbuf) < 0) {

    fprintf(stderr,"pcap_findalldevs(): %s\n",errbuf);

    return;
  }

  for(i = 0, dev = devices; dev; dev = dev->next, ++i) {

    fprintf(stderr,"%d: %s\n",i,dev->name);
  }

  pcap_freealldevs(devices);  
  
  return;
}

/*
 *
 */

void packet_handler(u_char *args,const struct pcap_pkthdr *header,const u_char *packet) {

  int            i, offset = 36, length, typ, len;
  char           ssid_tmp[32];
  u_char        *payload, *val, mac[6];
  u_int16_t     *radiotap_len; 
  static u_char  nan_cluster[6]  = {0x50, 0x6f, 0x9a, 0x01, 0x00, 0xff},
                 nan_service[6]  = {0x88, 0x69, 0x19, 0x9d, 0x92, 0x09},
                 oui_alliance[3] = {0x50, 0x6f, 0x9a};

  ssid_tmp[0]  =
  ssid_tmp[32] = 0;

  ++rx_packets;
  
  length       = header->len;
  radiotap_len = (u_int16_t *) &packet[2];

  if (*radiotap_len < length) {
    
    payload = (u_char *)  &packet[*radiotap_len];

  } else {

#if 1
    printf("{ \"debug\" : \"%d, ",*radiotap_len);

    for (i = 0; i < 40; ++i) {

      printf("%02x ",packet[i]);
    }
        
    printf("\" }\n");
#endif
    return;
  }

  if (payload[0] == 0x80) { // beacon

    offset = 36;

    for (i = 0; i < 6; ++i) {

      mac[i] = payload[i + 10];
    }
    
    while (offset < length) {

      typ =  payload[offset];
      len =  payload[offset + 1];
      val = &payload[offset + 2];

      if ((typ    == 0xdd)&&
          (val[0] == 0xfa)&& // ODID
          (val[1] == 0x0b)&&
          (val[2] == 0xbc)) {

        parse_odid(mac,&payload[offset + 7],length - offset - 7);
 
      } else if ((typ    == 0xdd)&&
                 (val[0] == oui_alliance[0])&& // WiFi Alliance
                 (val[1] == oui_alliance[1])&&
                 (val[2] == oui_alliance[2])) {
#if 0
        printf("{ \"debug\" : \"Beacon with Alliance OUI\" }\n");
#else
        ;
#endif

      } else if ((typ    == 0xdd)&&
                 (val[0] == 0x6a)&& // French ID
                 (val[1] == 0x5c)&&
                 (val[2] == 0x35)) {
#if ID_FRANCE
        parse_id_france(mac,&payload[offset],RID_data);
#else
        printf("{ \"debug\" : \"French ID\" }\n");
#endif

      } else if ((typ == 0)&&(!ssid_tmp[0])) {

        for (i = 0; (i < 32)&&(i < len); ++i) {

          ssid_tmp[i] = val[i];
        }
      }

      offset += len + 2;
    }

  } else {

#if 0

    printf("{ \"debug\" : \"%d | ",length);

    for (i = 0; i < 24; ++i) {

      printf("%02x ",payload[i]);
    }
     
    printf("| ");

    for (i = 44; i < 60; ++i) {

      printf("%02x ",payload[i]);
    }
     
    printf("\" }\n");
    
#endif
    
    if (memcmp(nan_cluster,&payload[16],6) == 0) { // NAN

      offset = 24;

      if ((length > 44)&&
          (payload[offset]     == 0x04)&&
          (payload[offset + 1] == 0x09)&&
          (payload[offset + 2] == oui_alliance[0])&&
          (payload[offset + 3] == oui_alliance[1])&&
          (payload[offset + 4] == oui_alliance[2])&&
          (memcmp(nan_service,&payload[offset + 9],6) == 0)) {

        /* printf("{ \"debug\" : \"NAN action frame\" }\n"); */

        offset += 20;
      
        parse_odid(mac,&payload[offset],length - offset);
      }
    }
  }

  return;
}

/*
 *
 */

void parse_odid(u_char *mac,u_char *payload,int length) {

  int                       i, oldest, RID_index, page;
  char                      c;
  time_t                    secs, oldest_secs;
  ODID_UAS_Data             UAS_data;
  ODID_MessagePack_encoded *encoded_data = (ODID_MessagePack_encoded *) payload;

  i = 0;

  ++odid_packets;

  memset(&UAS_data,0,sizeof(UAS_data));

  decodeMessagePack(&UAS_data,encoded_data);

  /* Find the record to store the decoded data in. */
  
  time(&secs);

  RID_index   =
  oldest      = 0;
  oldest_secs = secs;
  
  for (i = 0; i < MAX_UAVS; ++i) {

    if (memcmp(mac,RID_data[i].mac,6) == 0) {

      RID_index           = i;
      RID_data[i].last_rx = secs;

      break;
    }
    
    if (RID_data[i].last_rx < oldest_secs) {

      oldest      = i;
      oldest_secs = RID_data[i].last_rx;
    }
  }

  if (i == MAX_UAVS) {

    struct UAV_RID *uav;

    uav = &RID_data[oldest];

    if (uav->mac[0]) {

      fprintf(stderr,"Reusing RID record %d (%02x:%02x:%02x:%02x:%02x:%02x)\n",oldest,
              uav->mac[0],uav->mac[1],uav->mac[2],
              uav->mac[3],uav->mac[4],uav->mac[5]);
    }

    RID_index      = oldest;
    uav->last_rx   = secs;
    uav->last_retx = 0;
    uav->packets   = 0;

    memcpy(uav->mac,mac,6);
    memset(&uav->odid_data,0,sizeof(ODID_UAS_Data));
  }

  ++RID_data[RID_index].packets;

  /* JSON */
  
  printf("{ \"mac\" : \"%02x:%02x:%02x:%02x:%02x:%02x\"",
         mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);

  if (UAS_data.OperatorIDValid) {

    printf(", \"operator\" : \"%s\"",UAS_data.OperatorID.OperatorId);

    memcpy(&RID_data[RID_index].odid_data.OperatorID,&UAS_data.OperatorID,sizeof(ODID_OperatorID_data));
  }

  if (UAS_data.BasicIDValid[0]) {

    printf(", \"uav id\" : \"%s\"",UAS_data.BasicID[0].UASID);

    memcpy(&RID_data[RID_index].odid_data.BasicID[0],&UAS_data.BasicID[0],sizeof(ODID_BasicID_data));
  }
  
  if (UAS_data.BasicIDValid[1]) {

    memcpy(&RID_data[RID_index].odid_data.BasicID[1],&UAS_data.BasicID[1],sizeof(ODID_BasicID_data));
  }
  
  if (UAS_data.LocationValid) {

    printf(", \"uav latitude\" : %11.6f, \"uav longitude\" : %11.6f",
           UAS_data.Location.Latitude,UAS_data.Location.Longitude);
    printf(", \"uav altitude\" : %d, \"uav heading\" : %d",
           (int) UAS_data.Location.AltitudeGeo,(int) UAS_data.Location.Direction);
    printf(", \"uav speed\" : %d, \"seconds\" : %d",
           (int) UAS_data.Location.SpeedHorizontal,(int) UAS_data.Location.TimeStamp);

    memcpy(&RID_data[RID_index].odid_data.Location,&UAS_data.Location,sizeof(ODID_Location_data));
  }
  
  if (UAS_data.SystemValid) {

    printf(", \"base latitude\" : %11.6f, \"base longitude\" : %11.6f",
           UAS_data.System.OperatorLatitude,UAS_data.System.OperatorLongitude);
    printf(", \"unix time\" : %lu",
           ((unsigned long int) UAS_data.System.Timestamp) + ID_OD_AUTH_DATUM);

    memcpy(&RID_data[RID_index].odid_data.System,&UAS_data.System,sizeof(ODID_System_data));
  }

  if (UAS_data.SelfIDValid) {

    memcpy(&RID_data[RID_index].odid_data.SelfID,&UAS_data.SelfID,sizeof(ODID_SelfID_data));
  }

  for (page = 0; page < ODID_AUTH_MAX_PAGES; ++page) {
  
    if (UAS_data.AuthValid[page]) {

      if (page == 0) {

        printf(", \"unix time (alt)\" : %lu",
               ((unsigned long int) UAS_data.Auth[page].Timestamp) + ID_OD_AUTH_DATUM);
      }

      printf(", \"auth page %d\" : { \"text\" : \"",page);

      for (i = 0; i < ((page) ? ODID_AUTH_PAGE_NONZERO_DATA_SIZE: ODID_AUTH_PAGE_ZERO_DATA_SIZE); ++i) {

        c = (char) UAS_data.Auth[page].AuthData[i];

        putchar((isprint(c)&&(c != fwd_slash)) ? c: '.');
      }

      printf("\"");
#if 1
      printf(", \"values\" : [");
    
      for (i = 0; i < ((page) ? ODID_AUTH_PAGE_NONZERO_DATA_SIZE: ODID_AUTH_PAGE_ZERO_DATA_SIZE); ++i) {

        printf("%s %d",(i) ? ",":"",UAS_data.Auth[page].AuthData[i]);
      }

      printf(" ]");
#endif
      printf(" }");
    
      memcpy(&RID_data[RID_index].odid_data.Auth[page],&UAS_data.Auth[page],sizeof(ODID_Auth_data));
    }
  }

#if VERIFY

  parse_auth(&UAS_data,encoded_data);

#endif

  printf(" }\n");

  /* */
  
#if 0
  for (i = 0; (i < length)&&(i < 16); ++i) {

    fprintf(stderr,"%02x ",payload[i]);
  }
  
  for (i = 0; (i < length)&&(i < 16); ++i) {

    fprintf(stderr,"%c",(isprint(payload[i])&&(payload[i] != fwd_slash)) ? payload[i]: '.');
  }

  fprintf(stderr,"\n");
#endif

  return;
}

/*
 *
 */

void signal_handler(int sig) {

  end_program = 1;
  
  return;
}

/*
 *
 */

void dump(char *name,uint8_t *data,int len) {

  int i;
  
  if (debug_file) {

    fprintf(debug_file,"%s[] = {",name);

    for (i = 0; i < len; ++i) {

      fprintf(debug_file,"%s 0x%02x",(i) ? ",": "",data[i]);
    }
    
    fprintf(debug_file," };\n%s_s = \"",name);

    for (i = 0; i < len; ++i) {

      putc((isprint(data[i])&&data[i] != fwd_slash) ? data[i]: '.',debug_file);
    }
    
    fprintf(debug_file,"\";\n");

    fflush(debug_file);
  }
  
  return;
}

/*
 *
 */

