/* -*- tab-width: 2; mode: c; -*-
 * 
 * A program for capturing opendroneid / ASTM F3411 / ASD-STAN 4709-002 
 * WiFi beacon direct remote identification signals.
 *
 * This file has the code to interface with bluez.
 *
 * Copyright (c) 2022 Steve Jack
 *
 * MIT licence
 *
 * Notes
 *
 * Documentation for bluez is a bit thin on the ground...
 * My thanks to all people who publish example code.
 *
 * On the Pi 3B, running the bluez scanner seems to make the wifi stutter.
 *
 *
 */

#pragma GCC diagnostic warning "-Wunused-variable"
// #pragma GCC diagnostic ignored "-Wunused-but-set-variable"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <time.h>

#include <sys/ioctl.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include "rid_capture.h"

#define BLE_BUFFER_SIZE  256

static int            sniffer = -1, scanning = 0;
static const int      timeout = 1000, on = 1;
static volatile int   end_main = 0;
static uint32_t       counter = 1;

#if STANDALONE
static struct hci_version        hci_ver;
#endif
static le_set_scan_parameters_cp ble_scan_params;
static le_set_event_mask_cp      event_mask;
static le_set_scan_enable_cp     scan_enable;

static void create_request(struct hci_request *,uint16_t,void *,int);

#if STANDALONE

static void     main_signal_handler(int);

/*
 *
 */

int main(int argc, char *argv[]) {

  int status = 0;

  /*
   */
  
  signal(SIGINT,main_signal_handler);
  
  if ((status = start_bluez_sniffer("hci0")) == 0) {

    while (!end_main) {

      parse_bluez_sniffer();
    }

    stop_bluez_sniffer();
  }

  fprintf(stderr,"\n");
  
  exit(0);
}

#endif

/*
 *
 */

pid_t start_bluez_sniffer(const char *device) {

  int                        status = 0, dev;
  uint8_t                   *status_u8;
  static struct hci_request  request;
  static struct hci_filter   filter;
 
  dev = device[3] - '0';

  if ((dev < 0)||(dev > 9)) {
    return -1;
  }

  if ((sniffer = hci_open_dev(dev)) < 0) {

    fprintf(stderr,"%s(): error opening hci%d, %d, %s\n",
            __func__,dev,sniffer,strerror(sniffer));
    return sniffer;
  }

  if ((status = ioctl(sniffer,FIONBIO,&on)) < 0) { // Should find a way to use O_NONBLOCK?

    fprintf(stderr,"%s(): ioctl() returned %d, %s\n",
            __func__,status,strerror(status));
    /* stop_bluez_sniffer();
       return status; */
  }

#if STANDALONE
  memset(&hci_ver,0,sizeof(hci_ver));

  if ((status = hci_read_local_version(sniffer,&hci_ver,timeout)) < 0) {

    fprintf(stderr,"hci_read_local_version() returned  %d, %s\n",
            status,strerror(status));
    stop_bluez_sniffer();
    return status;
  }

  fprintf(stderr,"bluez local version: hci %02x %04x, lmp %02x %04x, manf. %04x\n",
          hci_ver.hci_ver,hci_ver.hci_rev,
          hci_ver.lmp_ver,hci_ver.lmp_subver,
          hci_ver.manufacturer);
#endif

  // hci_le_set_scan_parameters
  memset(&ble_scan_params,0,sizeof(ble_scan_params));

  ble_scan_params.interval = htobs(0x10);
  ble_scan_params.window   = htobs(0x10);

  create_request(&request,OCF_LE_SET_SCAN_PARAMETERS,&ble_scan_params,
                 LE_SET_SCAN_PARAMETERS_CP_SIZE);

  status    = hci_send_req(sniffer,&request,timeout);
  status_u8 = request.rparam;
  
  if ((status)||(*status_u8)) {

    fprintf(stderr,"hci_send_req(scan parameters) returned %d, %s, %02x\n",
            status,strerror(status),(unsigned int) *status_u8);
    stop_bluez_sniffer();
    return status;
  }

  memset(&event_mask,     0,   sizeof(event_mask));
  memset(&event_mask.mask,0xff,sizeof(event_mask.mask));

  create_request(&request,OCF_LE_SET_EVENT_MASK,&event_mask,
                 LE_SET_EVENT_MASK_CP_SIZE);

  status    = hci_send_req(sniffer,&request,timeout);
  status_u8 = request.rparam;

  if ((status)||(*status_u8)) {

    fprintf(stderr,"hci_send_req(event mask) returned  %d, %s, %02x\n",
            status,strerror(status),(unsigned int) *status_u8);
    stop_bluez_sniffer();
    return status;
  }

  // hci_le_set_advertise_enable
  memset(&scan_enable,0,sizeof(scan_enable));

  scan_enable.enable     = 0x01;
  scan_enable.filter_dup = 0x00;

  create_request(&request,OCF_LE_SET_SCAN_ENABLE,&scan_enable,
                 LE_SET_SCAN_ENABLE_CP_SIZE);

  status    = hci_send_req(sniffer,&request,timeout);
  status_u8 = request.rparam;

  if ((status)||(*status_u8)) {

    fprintf(stderr,"hci_send_req(scan enable) returned  %d, %s, %02x\n",
            status,strerror(status),(unsigned int) *status_u8);
    stop_bluez_sniffer();
    return status;
  }

  scanning = 1;

  hci_filter_clear(&filter);
  hci_filter_set_ptype(HCI_EVENT_PKT,&filter);
  hci_filter_set_event(EVT_LE_META_EVENT,&filter);

  if ((status = setsockopt(sniffer,SOL_HCI,HCI_FILTER,&filter,sizeof(filter))) < 0) {

    fprintf(stderr,"setsockopt(sniffer filter) returned  %d, %s\n",
            status,strerror(status));
    stop_bluez_sniffer();
    return status;
  }

  return 0;
}

/*
 *
 */

static void create_request(struct hci_request *request,uint16_t ocf,void *cparam,int clen) {

  static uint8_t status;

  status = 0;

  memset(request,0,sizeof(struct hci_request));

  request->ogf    = OGF_LE_CTL;
  request->ocf    = ocf;
  request->cparam = cparam;
  request->clen   = clen;
  request->rparam = &status;
  request->rlen   = 1;

  return;
}

/*
 *
 */

int parse_bluez_sniffer() {

  int                  i, offset = 1, adverts = 0, bytes;
  char                 address[18];
  uint8_t              buffer[HCI_MAX_EVENT_SIZE], mac[6];
  evt_le_meta_event   *event;
  le_advertising_info *advert;

  event = (evt_le_meta_event *) &buffer[HCI_EVENT_HDR_SIZE + 1];

  if ((bytes = read(sniffer,buffer,sizeof(buffer))) > HCI_EVENT_HDR_SIZE) {

    if (event->subevent == EVT_LE_ADVERTISING_REPORT) {
      
      ++counter;

      for (i = 0, offset = 1; i < event->data[0]; ++i) {

        memset(mac,0,sizeof(mac));
        advert = (le_advertising_info *) &event->data[offset];

        ba2str(&advert->bdaddr,address);
        sscanf(address,"%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX",
               &mac[0],&mac[1],&mac[2],&mac[3],&mac[4],&mac[5]);
#if STANDALONE
        fprintf(stderr,"%02x:%02x:%02x:%02x:%02x:%02x ",
                mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
        for (int j = 0; j < advert->length; ++j) {
          fprintf(stderr," %02x",advert->data[j]);
        }
        fputs("\n",stderr);
#else
        const int odid_offset = 5;

        if ((advert->data[1] == 0x16)&&
            (advert->data[2] == 0xfa)&&
            (advert->data[3] == 0xff)) {

          ++adverts;

          parse_odid(mac,&advert->data[odid_offset],advert->length - odid_offset,0);
        }
#endif
        offset += advert->length + 2;
      }
    }
  }

  return adverts;
}

/*
 *
 */

void stop_bluez_sniffer() {

  static struct hci_request request;
  
  if (sniffer >= 0) {

    if (scanning) {

      memset(&scan_enable,0,sizeof(scan_enable));

      create_request(&request,OCF_LE_SET_SCAN_ENABLE,&scan_enable,
                     LE_SET_SCAN_ENABLE_CP_SIZE);

      hci_send_req(sniffer,&request,timeout);

      scanning = 0;
    }

    hci_close_dev(sniffer);
    sniffer = -1;
  }

  return;
}

/*
 *
 */

#if STANDALONE

static void main_signal_handler(int sig) {

  end_main = 1;

  return;
}

#endif

/*
 *
 */

