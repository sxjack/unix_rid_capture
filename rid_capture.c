/* -*- tab-width: 2; mode: c; -*-
 * 
 * A program for capturing opendroneid / ASTM F3411 / ASD-STAN 4709-002 
 * WiFi beacon direct remote identification signals.
 *
 * Copyright (c) 2022-2023 Steve Jack
 *
 * MIT licence
 *
 * Options
 *
 * See the print_help() function.
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
 * Keep an eye on the main loop time. It may require tuning if you are using the 
 * display or exporting.
 *
 *
 * To Do
 *
 * Sort out the hangs that can occur if there is no data being received.
 *
 * Fully setup the WiFi device.
 *
 */

#define DEBUG_FILE 1

#pragma GCC diagnostic warning "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <pwd.h>

#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <sys/wait.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "rid_capture.h"

#if ENABLE_PCAP
#include <pcap/pcap.h>
#endif

#define BUFFER_SIZE     2048
#define MAX_KEY_LEN       16
#define NRF_BUFFER_SIZE  128

unsigned char             key[MAX_KEY_LEN + 2], iv[MAX_KEY_LEN + 2];
uid_t                     nobody  = 1000;
gid_t                     nogroup = 1000;
const mode_t              file_mode = 0666, dir_mode = 0777;

static int                enable_display = 0, enable_udp = 0, json_socket = -1,
                          max_udp_length = 0;
static char              *log_dir = NULL, *www_dir = NULL;
static double             setup_ms = 0.0, loop_us = 0.0;
static unsigned int       port = 32001;
static volatile int       end_program  = 0;
static FILE              *debug_file = NULL;
static const char         default_key[]     = "0123456789abcdef",
                          default_iv[]      = "nopqrs",
                          default_server[]  = "127.0.0.1",
                          debug_filename[]  = "debug.txt",
                          device_pi[]       = "wlan1",
                          device_i686[]     = "wlp5s0b1",
                          default_log_dir[] = "/tmp/rid_capture",
                          default_www_dir[] = "www",
                          dummy[]           = "";
const char                pass_s[] = "Pass", fail_s[] = "Fail"; 
static volatile uint32_t  rx_packets = 0, odid_packets = 0;
static struct UAV_RID     RID_data[MAX_UAVS];
static struct sockaddr_in server;
#if ENABLE_PCAP
static int                header_type = 0;
static const char        *filter_text = "ether broadcast or ether dst 51:6f:9a:01:00:00 ";
#endif
static const char         device_bluez[] = "hci0";
#if BLUEZ_SNIFFER
static int                ble_sniffer = -1;
#endif
static const char         device_nrf[] = "/dev/ttyACM0";
#if NRF_SNIFFER
static int                nrf_pipe = -1;
#endif
#if FA_EXPORT
static time_t             last_fa_export = 0;
#endif
#if ASTERIX
static time_t             last_asterix = 0;
#endif
#if WWW_PAGE
static time_t             last_www_page = 0;
#endif

#if ENABLE_PCAP
void list_devices(char *);
void packet_handler(u_char *,const struct pcap_pkthdr *,const u_char *);
#endif

static void print_help(void);
static void print_version(void);
static void signal_handler(int);

/*
 *
 */

int main(int argc,char *argv[]) {

  int                 i, j, set_monitor = 1, man_dev = 0, key_len, iv_len, status;
  char               *arg, *wifi_name, *nrf_name, *bluez_name, *udp_server,
                      text[128];
  uint32_t            packets_1s, last_odid_packets = 0;
  u_char              message[16];
  uid_t               uid;
  time_t              secs, last_debug = 0, last_diag = 0, last_summary = 0;
  struct timespec     start, setup_done, loop_entry, last_loop;
#if ENABLE_PCAP
  char                errbuf[PCAP_ERRBUF_SIZE];
  pcap_t             *session = NULL;
  bpf_u_int32         network = 0;
  struct bpf_program  filter;
#endif
  struct passwd      *user = NULL;
  struct utsname      sys_uname;
#if NRF_SNIFFER
  int                 bytes, nrf_bytes = 0, nrf_reads = 0;
  u_char              nrf_buffer[NRF_BUFFER_SIZE];
  pid_t               nrf_child;
#endif

  clock_gettime(CLOCK_REALTIME,&start);
  
  if (user = getpwnam("nobody")) {
    nobody  = user->pw_uid; 
    nogroup = user->pw_gid;
  }

  uid = geteuid();

  memset(&RID_data,0,sizeof(RID_data));
  memset(message,  0,sizeof(message));

  memset(key,0,sizeof(key));
  memset(iv, 0,sizeof(iv));

  memcpy(key,default_key,sizeof(default_key));
  memcpy(iv, default_iv, sizeof(default_iv));

  udp_server = (char *) default_server;
  wifi_name  = (char *) dummy;
  bluez_name = (char *) device_bluez;
  nrf_name   = (char *) device_nrf;
  log_dir    = (char *) default_log_dir;
  www_dir    = (char *) default_www_dir;

  uname(&sys_uname);
  
  if (!strncmp("i686",sys_uname.machine,4)) {
  
    wifi_name = (char *) device_i686;

  } else {

    wifi_name = (char *) device_pi;
  }

  /* Parse the command line. */
  
  for (i = 1; i < argc; ++i) {

    arg = argv[i];

    if (strcmp(arg,"--help") == 0) {
      print_help();
      exit(0);
    }
  
    if (strcmp(arg,"--version") == 0) {
      print_version();
      exit(0);
    }
  
    if (*arg == '-') {
      switch (arg[1]) {

      case 'h':
        print_help();
        exit(0);
        break;

      case 'b': /* Bluez device */
        if (++i < argc) {
          bluez_name = argv[i];
        }
        break;

      case 'd': /* Curses display */
        enable_display = 1;
        enable_udp     = 1;
        break;

      case 'f': /* nRF sniffer device */
        if (++i < argc) {
          nrf_name = argv[i];
        }
        break;

      case 'k': /* key */
        if (++i < argc) {
          strncpy((char *) key,argv[i],MAX_KEY_LEN);
        }
        break;

      case 'n': /* nonce/iv */
        if (++i < argc) {
          strncpy((char *) iv,argv[i],MAX_KEY_LEN);
        }
        break;

      case 's': /* UDP server */
        if (++i < argc) {
          udp_server = argv[i];
        }
        break;

      case 'p':
        if (++i < argc) {
          if ((j = atoi(argv[i])) > 1023) {
            port = j;
          }
        }
      // No break.

      case 'u': /* UDP output. */
        enable_udp = 1;
        break;

      case 'v':
        print_version();
        exit(0);
        break;

      case 'w': /* WiFi device */
        if (++i < argc) {
          wifi_name = argv[i];
        }
        break;

      case 'x': /* WiFi device already in monitor mode. */

        set_monitor = 0;
        break;
        
      default:
        break;
      }

    } else {

      man_dev     = 1;
    }
  }

  fprintf(stderr,"%s -w %s",argv[0],wifi_name);

#if VERIFY
  fprintf(stderr," -k \'%s\' -n \'%s\'",key,iv);
#endif

  if (!set_monitor) {
    fputs(" -x",stderr);
  }

  if (enable_udp) {
    fprintf(stderr," -p %u -s %s",port,udp_server);
  }

  fprintf(stderr,"\n%s %s\n",sys_uname.sysname,sys_uname.machine);

  signal(SIGINT,signal_handler);

  /* Somewhere to put the debug and summary files. */

  mkdir(log_dir,dir_mode);
  chmod(log_dir,dir_mode);
  chown(log_dir,nobody,nogroup);

#if WWW_PAGE
  mkdir(www_dir,dir_mode);
  chmod(www_dir,dir_mode);
  chown(www_dir,nobody,nogroup);
#endif

#if DEBUG_FILE
  sprintf(text,"%s/%s",log_dir,debug_filename);
  debug_file = fopen(text,"w");
  chmod(text,file_mode);
#endif

  if (enable_udp) {

    status = 0;

    if ((json_socket = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP)) >= 0) {

      memset(&server,0,sizeof(server));
      server.sin_family = AF_INET;
      server.sin_port   = htons(port);
      inet_aton(udp_server,&server.sin_addr);
    }
    
#if 0
    fprintf(stderr,"opening socket, %08x/%04x, %d\n",
            (uint32_t) server.sin_addr.s_addr,server.sin_port,json_socket);
#endif
  }
  
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

#if ENABLE_PCAP

  if (!(session = pcap_create(wifi_name,errbuf))) {
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

  if (pcap_lookupnet(wifi_name,&network,&netmask,errbuf) < 0) {
    fprintf(stderr,"pcap_lookupnet(%s): %s\n",wifi_name,errbuf);
  }

#endif

  if (i = pcap_activate(session)) {
    fprintf(stderr,"\npcap_activate():  %s, %s\n",
            pcap_geterr(session),pcap_strerror(i));
    fputs("This error may mean that you don\'t have permission to access your wifi hardware or that it is not capable of being put into monitor mode.\n",stderr);

    if (set_monitor) {
      fputs("Try setting monitor mode using iw and using the -x option to this program.\n",stderr);
    }

    if (uid) {
      fputs("You made need to run this program as root.\n",stderr);
    }

    fputs("\n",stderr);
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

#endif
  
#if BLUEZ_SNIFFER
  ble_sniffer = start_bluez_sniffer(bluez_name);
#endif

#if NRF_SNIFFER
  nrf_child = start_nrf_sniffer(nrf_name,&nrf_pipe);
#endif
  
  /* 
   */

  time(&secs);

  last_summary   =
  last_debug     = secs;
#if FA_EXPORT
  last_fa_export = secs + 2 + FA_EXPORT;
#endif
#if ASTERIX
  last_asterix   = secs + 3 + ASTERIX;
#endif
#if WWW_PAGE
  last_www_page  = secs + 4 + WWW_PAGE;
#endif

  clock_gettime(CLOCK_REALTIME,&setup_done);

  setup_ms = ((double) setup_done.tv_sec * 1e3 + (double) setup_done.tv_nsec * 1e-6) -
             ((double) start.tv_sec      * 1e3 + (double) start.tv_nsec      * 1e-6);
  
#if ENABLE_PCAP
  if (header_type != DLT_IEEE802_11_RADIO) {

      do {

        time(&secs);

      } while (secs < (last_debug + 2));
  }
#endif

  if (enable_display) {
    display_init();
  }

  sprintf(text,"{ \"setup_time_ms\" : %.0f }\n",setup_ms);
  write_json(text);

  clock_gettime(CLOCK_REALTIME,&last_loop);

  /* Main loop. */

  while (!end_program) {

    clock_gettime(CLOCK_REALTIME,&loop_entry);
    loop_us           = ((double) loop_entry.tv_sec * 1e6 + (double) loop_entry.tv_nsec * 1e-3) -
                        ((double) last_loop.tv_sec  * 1e6 + (double) last_loop.tv_nsec  * 1e-3);
    last_loop.tv_sec  = loop_entry.tv_sec;
    last_loop.tv_nsec = loop_entry.tv_nsec;

#if ENABLE_PCAP
    pcap_loop(session,1,packet_handler,message);
#endif

#if BLUEZ_SNIFFER
    if (ble_sniffer > -1) {
      for (j = 0; (j < 4)&&(!end_program); ++j) {

        if (parse_bluez_sniffer() < 1) {
          break;
        }
      }
    }
#endif

    // The nRF sniffer can put out a lot of data hence the separate process.

#if NRF_SNIFFER
    if (nrf_child > 0) {
      for (nrf_reads = 0, nrf_bytes = 0; (nrf_reads < 4)&&(!end_program);) {

        if ((bytes = read(nrf_pipe,nrf_buffer,sizeof(nrf_buffer))) > 0) {

          nrf_bytes += bytes;
          parse_nrf_sniffer(nrf_buffer,bytes);
        }

        ++nrf_reads;

        if (bytes < sizeof(nrf_buffer)) {
          break;
        }
      }
    }
#endif

    time(&secs);

    if ((secs - last_debug) > 9) {

      sprintf(text,"{ \"debug\" : \"rx packets %u (%u)\", \"loop_time_us\" : %.0f, \"max udp len\" : %d }\n",
              rx_packets,odid_packets,loop_us,max_udp_length);
      write_json(text);
#if NRF_SNIFFER
      sprintf(text,"{ \"nrf_reads\" : %d, \"nrf_bytes\" : %d }\n",
              nrf_reads,nrf_bytes);
      write_json(text);
#endif      
      last_debug = secs;
    }

#if 0
    if ((odid_packets % 20) == 19) {

      write(2,".",1);
    }
#endif

    if ((secs - last_summary) > 899) {

      print_summary(log_dir,NULL,RID_data,MAX_UAVS);
      last_summary = secs;
    }

    if (secs != last_diag) {

      packets_1s        = odid_packets - last_odid_packets;
      last_odid_packets = odid_packets;

      display_loop_diag(loop_us,packets_1s);

      last_diag = secs;
    }

#if ASTERIX > 0
    if ((secs - last_asterix) >= ASTERIX) {
      asterix_transmit(RID_data);
      last_asterix = secs;
    }
#endif

#if FA_EXPORT > 0
    if ((secs - last_fa_export) >= FA_EXPORT) {
      fa_export(secs,RID_data);
      last_fa_export = secs;
    }
#endif

#if WWW_PAGE > 0
    if ((secs - last_www_page) >= WWW_PAGE) {
      www_export(www_dir,secs,RID_data);
      last_www_page = secs;
    }
#endif
  }

  /* 
   */

  display_end();

#if BLUEZ_SNIFFER
  stop_bluez_sniffer();
#endif

#if NRF_SNIFFER
  time_t term_sent;
  
  if (nrf_child > 0) {
    kill(nrf_child,SIGTERM);
  }

  time(&term_sent);
#endif

#if VERIFY
  close_crypto();
#endif

#if ENABLE_PCAP
  pcap_close(session);
#endif

  if (enable_udp) {
    close(json_socket);
  }

  print_summary(log_dir,stderr,RID_data,MAX_UAVS);

  if (debug_file) {

    fclose(debug_file);
  }

#if NRF_SNIFFER
  if (nrf_child > 0) {

    fputs("\nWaiting for child process ",stderr);
 
    int wstatus;

    for (i = 0; i < 10; ++i) {
      
      if (waitpid(nrf_child,&wstatus,WNOHANG) > 0) {
        break;
      }

      write(2,"*",1);
      time(&secs);

      if ((secs - term_sent) > 4) {
        kill(nrf_child,SIGKILL);
      }
      
      sleep(1);
    }
  }
#endif

  fprintf(stderr,"\n");

  exit(0);
}

/*
 *
 */

#if ENABLE_PCAP

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
  char           ssid_tmp[32], text[128];
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
    sprintf(text,"{ \"debug\" : \"%d, ",*radiotap_len);
    write_json(text);

    for (i = 0; i < 40; ++i) {

      sprintf(text,"%02x ",packet[i]);
      write_json(text);
    }
        
    write_json("\" }\n");
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

        parse_odid(mac,&payload[offset + 6],length - offset - 6,0,"pcap beacon",NULL);
 
      } else if ((typ    == 0xdd)&&
                 (val[0] == oui_alliance[0])&& // WiFi Alliance
                 (val[1] == oui_alliance[1])&&
                 (val[2] == oui_alliance[2])) {
#if 0
        write_json("{ \"debug\" : \"Beacon with Alliance OUI\" }\n");
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
        write_json("{ \"debug\" : \"French ID\" }\n");
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
    sprintf(text,"{ \"debug\" : \"%d | ",length);
    write_json(text);

    for (i = 0; i < 24; ++i) {

      sprintf(text,"%02x ",payload[i]);
      write_json(text);
    }
     
    write_json("| ");

    for (i = 44; i < 60; ++i) {

      sprintf(text,"%02x ",payload[i]);
      write_json(text);
    }
     
    write_json("\" }\n");
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

        /* write_json("{ \"debug\" : \"NAN action frame\" }\n"); */

        offset += 19;
      
        parse_odid(mac,&payload[offset],length - offset,0,"pcap NAN",NULL);
      }
    }
  }

  return;
}

#endif // PCAP

/*
 *
 */

void parse_odid(u_char *mac,u_char *payload,int length,int rssi,const char *note,const float *volts) {

  int                       i, j, RID_index, page, authenticated;
  char                      json[128];
  uint8_t                   counter, index;
  double                    latitude, longitude, altitude;
  ODID_UAS_Data             UAS_data;
  ODID_MessagePack_encoded *encoded_data = (ODID_MessagePack_encoded *) &payload[1];

  i             = 0;
  authenticated = 0;

  /* */

  RID_index = mac_index(mac,RID_data);

  /* Decode */

  counter = payload[0];
  index   = payload[1] >> 4;

#if 1
  if (RID_data[RID_index].counter[index] == counter) {
    return;
  }
#endif

  RID_data[RID_index].counter[index] = counter;

  ++odid_packets;
  ++RID_data[RID_index].packets;
  RID_data[RID_index].rssi = rssi;

  if (note) {
    display_note(RID_index + 1,note);
  }
  
  if (volts) {
    display_voltage(RID_index + 1,*volts);
  }

  memset(&UAS_data,0,sizeof(UAS_data));

  switch (payload[1] & 0xf0) {

  case 0x00:
    decodeBasicIDMessage(&UAS_data.BasicID[0],(ODID_BasicID_encoded *) &payload[1]);
    UAS_data.BasicIDValid[0] = 1;
    break;
 
  case 0x10:
    decodeLocationMessage(&UAS_data.Location,(ODID_Location_encoded *) &payload[1]);
    UAS_data.LocationValid = 1;
    break;

  case 0x20:
    page = payload[2] & 0x0f;
    decodeAuthMessage(&UAS_data.Auth[page],(ODID_Auth_encoded *) &payload[1]);
    UAS_data.AuthValid[page] = 1;
    break;

  case 0x30:
    decodeSelfIDMessage(&UAS_data.SelfID,(ODID_SelfID_encoded *) &payload[1]);
    UAS_data.SelfIDValid = 1;
    break;

  case 0x40:
    decodeSystemMessage(&UAS_data.System,(ODID_System_encoded *) &payload[1]);
    UAS_data.SystemValid = 1;
    break;

  case 0x50:
    decodeOperatorIDMessage(&UAS_data.OperatorID,(ODID_OperatorID_encoded *) &payload[1]);
    UAS_data.OperatorIDValid = 1;
    break;

  case 0xf0:
    decodeMessagePack(&UAS_data,encoded_data);
    break;
  }
  
  /* JSON */

  sprintf(json,"{ \"mac\" : \"%02x:%02x:%02x:%02x:%02x:%02x\"",
          mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
  write_json(json);

#if 1
  sprintf(json,", \"rssi\" : %d",rssi);
  write_json(json);
#endif

#if 0
  sprintf(json,", \"debug\" : \"%d | ",length);
  write_json(json);

  for (i = 0; i < 16; ++i) {

    sprintf(json,"%02x ",payload[i]);
    write_json(json);
  }

  write_json("\"");
#endif

  if (UAS_data.OperatorIDValid) {

    sprintf(json,", \"operator\" : \"%s\"",UAS_data.OperatorID.OperatorId);
    write_json(json);

    memcpy(&RID_data[RID_index].odid_data.OperatorID,&UAS_data.OperatorID,sizeof(ODID_OperatorID_data));
    display_identifier(RID_index + 1,UAS_data.OperatorID.OperatorId);
  }

  for (j = 0; j < ODID_BASIC_ID_MAX_MESSAGES; ++j) {

    if (UAS_data.BasicIDValid[j]) {

      memcpy(&RID_data[RID_index].odid_data.BasicID[j],&UAS_data.BasicID[j],sizeof(ODID_BasicID_data));

      switch (UAS_data.BasicID[j].IDType) {

      case ODID_IDTYPE_SERIAL_NUMBER:
        memcpy(&RID_data[RID_index].basic_serial,&UAS_data.BasicID[j],sizeof(ODID_BasicID_data));
        sprintf(json,", \"uav id\" : \"%s\"",UAS_data.BasicID[j].UASID);
        write_json(json);
#if 0
        display_identifier(RID_index + 1,UAS_data.BasicID[j].UASID);
#endif
        break;
        
      case ODID_IDTYPE_CAA_REGISTRATION_ID:
        memcpy(&RID_data[RID_index].basic_caa_reg,&UAS_data.BasicID[j],sizeof(ODID_BasicID_data));
        sprintf(json,", \"caa registration\" : \"%s\"",UAS_data.BasicID[j].UASID);
        write_json(json);
        display_identifier(RID_index + 1,UAS_data.BasicID[j].UASID);
        break;
        
      case ODID_IDTYPE_NONE:
      default:
        break;
      }
    }
  }

  if (UAS_data.LocationValid) {

    latitude  = UAS_data.Location.Latitude;
    longitude = UAS_data.Location.Longitude;
    altitude  = UAS_data.Location.AltitudeGeo;

    sprintf(json,", \"uav latitude\" : %11.6f, \"uav longitude\" : %11.6f",
            latitude,longitude);
    write_json(json);
    sprintf(json,", \"uav altitude\" : %d, \"uav heading\" : %d",
           (int) UAS_data.Location.AltitudeGeo,(int) UAS_data.Location.Direction);
    write_json(json);
#if 0
    sprintf(json,", \"uav speed horizontal\" : %d, \"uav speed vertical\" : %d",
           (int) UAS_data.Location.SpeedHorizontal,(int) UAS_data.Location.SpeedVertical);
    write_json(json);
#endif
    sprintf(json,", \"uav speed\" : %d, \"seconds\" : %d",
           (int) UAS_data.Location.SpeedHorizontal,(int) UAS_data.Location.TimeStamp);
    write_json(json);

    memcpy(&RID_data[RID_index].odid_data.Location,&UAS_data.Location,sizeof(ODID_Location_data));

    display_uav_loc(RID_index + 1,latitude,longitude,
                    (int) altitude,(int) UAS_data.Location.TimeStamp);

    if ((latitude < RID_data[RID_index].min_lat)||(RID_data[RID_index].min_lat == 0.0)) {
      RID_data[RID_index].min_lat = latitude;
    }

    if ((latitude > RID_data[RID_index].max_lat)||(RID_data[RID_index].max_lat == 0.0)) {
      RID_data[RID_index].max_lat = latitude;
    }

    if ((longitude < RID_data[RID_index].min_long)||(RID_data[RID_index].min_long == 0.0)) {
      RID_data[RID_index].min_long = longitude;
    }

    if ((longitude > RID_data[RID_index].max_long)||(RID_data[RID_index].max_long == 0.0)) {
      RID_data[RID_index].max_long = longitude;
    }

    if (altitude > INV_ALT) {
    
      if ((altitude < RID_data[RID_index].min_alt)||(RID_data[RID_index].min_alt == 0.0)) {
        RID_data[RID_index].min_alt = altitude;
      }

      if ((altitude > RID_data[RID_index].max_alt)||(RID_data[RID_index].max_alt == 0.0)) {
        RID_data[RID_index].max_alt = altitude;
      }
    }
  }
  
  if (UAS_data.SystemValid) {

    sprintf(json,", \"base latitude\" : %11.6f, \"base longitude\" : %11.6f",
           UAS_data.System.OperatorLatitude,UAS_data.System.OperatorLongitude);
    write_json(json);
    sprintf(json,", \"unix time\" : %lu",
           ((unsigned long int) UAS_data.System.Timestamp) + ID_OD_AUTH_DATUM);
    write_json(json);

    memcpy(&RID_data[RID_index].odid_data.System,&UAS_data.System,sizeof(ODID_System_data));

    display_timestamp(RID_index + 1,(time_t) UAS_data.System.Timestamp + ID_OD_AUTH_DATUM);
  }

  if (UAS_data.SelfIDValid) {

    sprintf(json,", \"self id\" : \"%s\"",UAS_data.SelfID.Desc);
    write_json(json);

    memcpy(&RID_data[RID_index].odid_data.SelfID,&UAS_data.SelfID,sizeof(ODID_SelfID_data));
  }

  for (page = 0; page < ODID_AUTH_MAX_PAGES; ++page) {
  
    if (UAS_data.AuthValid[page]) {

      if (page == 0) {

        sprintf(json,", \"unix time (alt)\" : %lu",
               ((unsigned long int) UAS_data.Auth[page].Timestamp) + ID_OD_AUTH_DATUM);
        write_json(json);

        display_timestamp(RID_index + 1,(time_t) UAS_data.Auth[page].Timestamp + ID_OD_AUTH_DATUM);
      }

      sprintf(json,", \"auth page %d\" : { \"text\" : \"%s\"",page,
             printable_text(UAS_data.Auth[page].AuthData,
                            (page) ? ODID_AUTH_PAGE_NONZERO_DATA_SIZE: ODID_AUTH_PAGE_ZERO_DATA_SIZE));
      write_json(json);

#if 1
      write_json(", \"values\" : [");
    
      for (i = 0; i < ((page) ? ODID_AUTH_PAGE_NONZERO_DATA_SIZE: ODID_AUTH_PAGE_ZERO_DATA_SIZE); ++i) {

        sprintf(json,"%s %d",(i) ? ",":"",UAS_data.Auth[page].AuthData[i]);
        write_json(json);
      }

      write_json(" ]");
#endif
      write_json(" }");
    
      memcpy(&RID_data[RID_index].odid_data.Auth[page],&UAS_data.Auth[page],sizeof(ODID_Auth_data));
    }
  }

#if VERIFY
  authenticated = parse_auth(&UAS_data,encoded_data,&RID_data[RID_index]);
  display_pass(RID_index + 1,(authenticated)? pass_s: "    "); 
#endif

  write_json(" }\n");

  /* */
  
#if 0
  for (i = 0; (i < length)&&(i < 16); ++i) {

    fprintf(stderr,"%02x ",payload[i]);
  }
  
  fprintf(stderr,"%s\n",printable_text(payload,16));
#endif

  return;
}

/*
 *
 */

static void signal_handler(int sig) {

  end_program = 1;
  
  return;
}

/*
 * Function to find a record to store the decoded data in.
 *
 */

int mac_index(uint8_t *mac,struct UAV_RID *RID_data) {

  int    i, RID_index = 0, oldest = 0;
  char   text[64];
  time_t secs, oldest_secs;

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

    sprintf(text,"%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);

    display_mac(oldest + 1,mac);

    if (!enable_display) {

      fputs(text,stderr);

      if (uav->mac[0]) {

        fprintf(stderr," - reusing RID record %d (%02x:%02x:%02x:%02x:%02x:%02x)\n",oldest,
                uav->mac[0],uav->mac[1],uav->mac[2],
                uav->mac[3],uav->mac[4],uav->mac[5]);
      } else {

        fprintf(stderr," - using RID record %d\n",oldest);
      }
    }

    RID_index        = oldest;
    uav->last_rx     = secs;
    uav->last_retx   = 0;
    uav->packets     = 0;

    memcpy(uav->mac,mac,6);
    memset(&uav->odid_data, 0,sizeof(ODID_UAS_Data));

#if VERIFY
    uav->auth_length = 0;
    memset(uav->auth_buffer,0,sizeof(uav->auth_buffer));
#endif
  }

  return RID_index;
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
    
    fprintf(debug_file," };\n%s_s = \"%s\";\n",name,printable_text(data,len));

    fflush(debug_file);
  }
  
  return;
}

/*
 *
 *  \ is 0x5c
 */

char *printable_text(uint8_t *data,int len) {

  int    i;
  static char text[32];

  for (i = 0; (i < 31)&&(i < len); ++i) {

    text[i] = (isprint(data[i])&&(data[i] != '"')&&(data[i] != '\\')) ? (char) data[i]: '.';
  }

  text[i] = 0;

  return text;
}


/*
 *
 */

void print_version() {

  fprintf(stderr,"rid_capture version %s\r\n",VERSION);

  return;
}

/*
 *
 */

void print_help() {

  int          i;
  static const char *help_text[] =
    {"Options",
     "",
#if BLUEZ_SNIFFER
     "-b <bluez device>",
#endif
#if USE_CURSES
     "-d, basic text display",
#endif
#if NRF_SNIFFER
     "-f <tty>, the tty that an nRF52 sniffer is in",
#endif
     "-k <crypto key>",
     "-n <crypto initial vector>",
     "-p <UDP port>",
     "-s <UDP server>",
     "-u, enables UDP output",
#if ENABLE_PCAP
     "-w <WiFi device>",
#endif
     "-x, do not try to put the WiFi device into monitor",
     "",
     NULL },
                     crlf[] = "\r\n";

  for (i = 0; (i < 24)&&(help_text[i]); ++i) {

    fputs(help_text[i],stderr);
    fputs(crlf,stderr);
  }

  return;
}

/*
 *
 */

#define UDP_BUFFER_SIZE 800 // Should really be 500, but we can get close to 500 with packed messages. 

int write_json(char *json) {

  int            status;
#if UDP_BUFFER_SIZE
  static int     index = 0;
  static uint8_t udp_buffer[UDP_BUFFER_SIZE + 2], c;
#else
  int            l;
#endif
  
  if (json_socket > -1) {

#if UDP_BUFFER_SIZE
    while (*json) {

      udp_buffer[index++] = c = (uint8_t) *json++;

      if ((c     == 0x0a)||
          (c     == 0x0d)||
          (index >= UDP_BUFFER_SIZE)){

        udp_buffer[index] = 0;
        
        if ((status = sendto(json_socket,udp_buffer,index,0,
                             (struct sockaddr *) &server,sizeof(server))) < 0) {

          fprintf(stderr,"%s(): %d, %d, %d\n",
                  __func__,index,status,errno);
        }

        if (index > max_udp_length) {
          max_udp_length = index;
        }

        index = 0;
        break;
      }
    }
#else
    if ((status = sendto(json_socket,json,l = strlen(json),0,
                         (struct sockaddr *) &server,sizeof(server))) < 0) {

      fprintf(stderr,"%s(): %d, %d, %d\n",
              __func__,l,status,errno);
    }
#endif
  } else {

    fputs(json,stdout);
  }

  return 0;
}

/*
 *
 */

 
/*
 *
 */

