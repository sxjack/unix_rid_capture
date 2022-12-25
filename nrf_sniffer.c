/* -*- tab-width: 2; mode: c; -*-
 * 
 * A program for capturing opendroneid / ASTM F3411 / ASD-STAN 4709-002 
 * WiFi beacon direct remote identification signals.
 *
 * This file has code handle the interface with an NRF Sniffer.
 *
 * Copyright (c) 2022 Steve Jack
 *
 * MIT licence
 *
 * Notes
 *
 * nRF Sniffer data format from -
 * https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-nordic_ble.c
 *
 * My nRF Beacon is running version 4.1.1 of nRF's nRF52840 dongle sniffer firmware.
 *
 * The specification has a board ID at the start of the packet, but it doesn't seem to 
 * be there?
 * Need to investigate why it only works if we send single bytes down the pipe.
 *
 */

#pragma GCC diagnostic warning "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <termios.h>
#include <time.h>

#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/ioctl.h>

#include "rid_capture.h"

#define BLE_BUFFER_SIZE  256
#define SLIP_START      0xAB
#define SLIP_END        0xBC
#define SLIP_ESC        0xCD
#define SLIP_ESC_START  0xAC
#define SLIP_ESC_END    0xBD
#define SLIP_ESC_ESC    0xCE

#define REQ_SCAN_CONT   0x07
#define PING_REQ        0x0d
#define PING_RESP       0x0e
#define GO_IDLE         0xfe

#define BOARD_ID           0

static int              sniffer = -1, pipe_in = -1, pipe_out = -1;
static volatile int     end_main = 0, end_child = 0;
static uint16_t         counter = 1;
#if defined(BOARD_ID)
static const uint8_t    nrf_board_id = BOARD_ID;
#endif
static speed_t          baud_rates[] = {B460800, B1000000, 0, 0};
static struct termios   tty;

static uint8_t *nrf_sniffer_v3_encode(uint16_t *,uint8_t,uint8_t *,uint16_t);
static int      sniffer_encode_byte(uint8_t *,int,uint8_t);
static int      decode_sniffer_packet(uint8_t *,int);

static void     child_signal_handler(int);

#if STANDALONE

static void     main_signal_handler(int);

/*
 *
 */

int main(int argc, char *argv[]) {

  int             i, sniffer, bytes, wstatus, len2 = 23, len3;
  uint8_t         buffer[256], *buffer2;
  uint16_t        length;
  pid_t           child;
  static uint8_t  dummy_payload[] = {0x1e, 0x16, 0xfa, 0xff, 0x0d, 0x0d, 0x12, 0x00, 0x5e, 0x00,
                                     SLIP_START, SLIP_END, SLIP_ESC, 0x00,
                                     SLIP_ESC_START, SLIP_ESC_END, SLIP_ESC_ESC, 0x00,
                                     SLIP_START, SLIP_END, SLIP_ESC};

  fprintf(stderr,"\nChecking encode/decode.\nPayload: %25s","");
  
  memset(buffer,0,sizeof(buffer));

  buffer[0] = 0x0a;
  buffer[1] = 0x01;
  
  for (i = 0; i < 6; ++i) {
    buffer[len2 - 6 + i] = i + 17;
  }

  memcpy(&buffer[len2],dummy_payload,sizeof(dummy_payload));

  len3 = len2 + sizeof(dummy_payload);

  for (i = 0; i < len3; ++i) {

    if ((i == 0)||(i == 10)||(i == 23)) {
      fprintf(stderr,"| ");
    }

    fprintf(stderr,"%02x ",buffer[i]);
  }

  fprintf(stderr,"\n");
  
  buffer2 = nrf_sniffer_v3_encode(&length,0x06,buffer,len3);

  buffer[80] = SLIP_END;

  fprintf(stderr,"Encoded:   ");
  
  for (i = 0; i < length; ++i) {

    if ((i == 1)||(i == 7)||(i == 17)||(i == 30)) {
      fprintf(stderr,"| ");
    }
#if defined(BOARD_ID)
    fprintf(stderr,"%02x ",buffer2[i + 1]);
#else
    fprintf(stderr,"%02x ",buffer2[i]);
#endif
  }

  fprintf(stderr,"\nDecoded:     ");
  
#if defined(BOARD_ID)
  buffer2[1] = SLIP_START;
  parse_nrf_sniffer(&buffer2[1],length - 1);
#else
  parse_nrf_sniffer(buffer2,length);
#endif
  parse_nrf_sniffer(&buffer[80],1);
  
  fprintf(stderr,"\nChecks complete.\n");
  
  /*
   */
  
  signal(SIGINT,main_signal_handler);
  
  if ((child = start_nrf_sniffer("/dev/ttyACM0",&sniffer)) > 0) {

    while (!end_main) {

      if (bytes = read(pipe_out,buffer,16)) {

        parse_nrf_sniffer(buffer,bytes);
      }
    }

    kill(child,SIGTERM);
    wait(&wstatus);
  }

  fprintf(stderr,"\n");
  
  exit(0);
}

#endif

/*
 *
 */

pid_t start_nrf_sniffer(const char *device, int *_pipe) {

  int       status, pipefd[2], bytes, flags;
  uint8_t  *message, rx_buffer[16];
  uint16_t  length;
  pid_t     child = -1;

  *_pipe = -1;

  /* 
   * Open and setup the serial port to the nRF dongle/sniffer.
   * Serial I/O on unix is very old school.
   *
   * NON_BLOCK ?
   */

  if ((sniffer = open(device,O_RDWR | O_NOCTTY)) < 0) {

    fprintf(stderr,"%s(): Unable to open \'%s\', %d, %s\n",
            __func__,device,sniffer,strerror(sniffer));
    return sniffer;
  }

  if (status = tcgetattr(sniffer,&tty)) {

    fprintf(stderr,"%s(): tcgetattr() returned %d\n",__func__,status);
    close(sniffer);

    return -1;
  }

  tty.c_cflag    &=  ~CSIZE;
  tty.c_cflag    |=   CS8;
  tty.c_cflag    |=  (CLOCAL | CREAD);
  tty.c_cflag    &= ~(PARENB | PARODD);
  tty.c_cflag    &=  ~CSTOPB;
  tty.c_cflag    &=  ~CRTSCTS;

  tty.c_iflag    &= ~IGNBRK;
  tty.c_iflag    &= ~(IXON | IXOFF | IXANY);

  tty.c_lflag     = 0;
  tty.c_oflag     = 0;

  tty.c_cc[VMIN]  = 1;
  tty.c_cc[VTIME] = 1;
  
  cfsetospeed(&tty,baud_rates[1]);
  cfsetispeed(&tty,baud_rates[1]);
  
  if (status = tcsetattr(sniffer,TCSANOW,&tty)) {

    fprintf(stderr,"%s(): tcgetattr() returned %d\n",__func__,status);
    close(sniffer);

    return -1;
  }

  message = nrf_sniffer_v3_encode(&length,REQ_SCAN_CONT,NULL,0);
  write(sniffer,message,length);

  /*
   * Create a pipe and fork off a process to handle reading the serial link to the sniffer.
   */
  
  if ((status = pipe(pipefd)) < 0) {

    fprintf(stderr,"%s(): Unable to open pipe, %d, %s\n",
            __func__,sniffer,strerror(status));
    close(sniffer);

    return -1;
  }

  *_pipe   =
  pipe_out = pipefd[0];
  pipe_in  = pipefd[1];

	flags    = fcntl(pipe_out,F_GETFD);
	flags   |= O_NONBLOCK;
	
  if ((status = fcntl(pipe_out,F_SETFD,flags)) < 0) {

    fprintf(stderr,"%s(): fcntl() returned %d, %s\n",
            __func__,status,strerror(status));
	}	
	
  if ((child = fork()) == 0) {

    signal(SIGINT,child_signal_handler);
    signal(SIGTERM,child_signal_handler);
  
    while (!end_child) {

      if (bytes = read(sniffer,rx_buffer,1) > 0) {
        write(pipe_in,rx_buffer,bytes);
      }

#if 0 /* Causes problems? */
      message = nrf_sniffer_v3_encode(&length,GO_IDLE,NULL,0);
      write(sniffer,message,length);
#endif
    }

    exit(0);
  }

  return child;
}

/*
 *
 */

void parse_nrf_sniffer(uint8_t *buffer,int bytes) {

  int            i;
  uint8_t        c;
  static int     started = 0, escaped = 0;
  static int     rx_index = 0;
  static uint8_t rx_buffer[BLE_BUFFER_SIZE];

  for (i = 0; i < bytes; ++i) {

    c = buffer[i];
          
    if (started) {

      if (escaped) {

        switch (c) {

        case SLIP_ESC_START:
          rx_buffer[rx_index++] = SLIP_START;
          break;

        case SLIP_ESC_END:
          rx_buffer[rx_index++] = SLIP_END;
          break;

        case SLIP_ESC_ESC:
          rx_buffer[rx_index++] = SLIP_ESC;
          break;
        }

        escaped = 0;
      
      } else {

        switch (c) {

        case SLIP_ESC:
          escaped = 1;
          break;

        case SLIP_END:
          decode_sniffer_packet(rx_buffer,rx_index);
          rx_index = 0;
          started  = 0;
          escaped  = 0;
          break;

        default:
          rx_buffer[rx_index++] = c;
          break;
        }
      }
            
    } else if (c == SLIP_START) {

      started  = 1;
      rx_index = 0;
    }

    if (rx_index > (BLE_BUFFER_SIZE - 4)) {

      rx_index = 0;
      started  = 0;
      escaped  = 0;
    }
  }
  
  return;
}

/*
 *
 */

void stop_nrf_sniffer() {

  end_child = 1;
  
  return;
}

/*
 *
 */

static uint8_t *nrf_sniffer_v3_encode(uint16_t *encoded_length,uint8_t packet_id,
                                      uint8_t *payload,uint16_t payload_length) {

  int            i;
  uint16_t       j = 0;
  static uint8_t buffer[BLE_BUFFER_SIZE + 2];

  buffer[j++] = SLIP_START;

#if defined(BOARD_ID)
  j = sniffer_encode_byte(buffer,j,nrf_board_id);
#endif
  j = sniffer_encode_byte(buffer,j,(uint8_t)  payload_length);
  j = sniffer_encode_byte(buffer,j,(uint8_t) (payload_length  >> 8));
  buffer[j++] = 3;
  j = sniffer_encode_byte(buffer,j,(uint8_t)  counter);
  j = sniffer_encode_byte(buffer,j,(uint8_t) (counter >> 8));
  buffer[j++] = packet_id;

  ++counter;

  if (payload) {

    for (i = 0; (i < payload_length)&&(j < BLE_BUFFER_SIZE); ++i) {

      j = sniffer_encode_byte(buffer,j,payload[i]);
    }
  }

  buffer[j++] = SLIP_END;

  *encoded_length = j;
  
  return buffer;
}

/*
 *
 */

static int sniffer_encode_byte(uint8_t *buffer,int index,uint8_t byte) {

  switch (byte) {

  case SLIP_START:
    buffer[index++] = SLIP_ESC;
    buffer[index++] = SLIP_ESC_START;
    break;

  case SLIP_END:
    buffer[index++] = SLIP_ESC;
    buffer[index++] = SLIP_ESC_END;
    break;

  case SLIP_ESC:
    buffer[index++] = SLIP_ESC;
    buffer[index++] = SLIP_ESC_ESC;
    break;

  default:
    buffer[index++] = byte;
    break;
  }
  
  return index;
}

/*
 *
 */

int decode_sniffer_packet(uint8_t *message,int msg_len) {

  int      i, offset1, offset2 = 0, crc_ok = 0;
  uint8_t  packet_id, version, *adv_data, *payload = NULL, mac[6];
  uint16_t payload_len, counter;

  if (msg_len < 6) {
    return 0;
  }

  payload_len =  message[0] | (message[1] << 8);
  version     =  message[2];
  counter     =  message[3] | (message[4] << 8);
  packet_id   =  message[offset1 = 5];

#if 0
  fprintf(stderr,"%s(%08x,%d) v %d, id %02x\n",__func__,
          (unsigned int) message,msg_len,version,packet_id);
#endif
  
  if (version == 3) {

    switch (packet_id) {

    case 0x02:
    case 0x06:

      if ((payload_len > 22)&&
          (payload_len < (BLE_BUFFER_SIZE - 10))) {
 
        payload  = &message[offset1 + 1];  
        offset2  = payload[0];
        crc_ok   = payload[1] & 0x01;

        adv_data = &payload[offset2 + 13];

        for (i = 0; i < 6; ++i) {

          mac[i] = payload[offset2 + 12 - i];
        }
    
#if STANDALONE
        fprintf(stderr,"%2d %3d %d %6d %02x %d |",
                msg_len,payload_len,version,counter,packet_id,crc_ok);

        for (i = 0; (i < payload_len)&&(i < 44); ++i) {

          if ((i == offset2)||(i == (offset2 + 13))) {
            fputs(" |",stderr);
          }

          fprintf(stderr," %02x",payload[i]);
        }

        fprintf(stderr,"\n");
#else
        if ((adv_data[1] == 0x16)&&
            (adv_data[2] == 0xfa)&&
            (adv_data[3] == 0xff)&&
            (crc_ok)) {

          parse_odid(mac,&adv_data[5],payload_len - offset2 - 17,-payload[3]);
        }
#endif
      }
      break;

    case 0x0e: /* ping */
      break;

    default:
      break;
    }
  }

  return 0;
}

/*
 *
 */

static void child_signal_handler(int sig) {

  end_child = 1;

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

