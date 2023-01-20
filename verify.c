/* -*- tab-width: 2; mode: c; -*-
 * 
 * A program for capturing opendroneid / ASTM F3411 / ASD-STAN 4709-002 
 * WiFi beacon direct remote identification signals.
 *
 * This file contains the code for investigating authentication messages.
 * To use it, set VERIFY to 1 in rid_capure.h and add -lgcrypt to the 
 * libraries in the Makefile.
 *
 * Experimental.
 *
 * Copyright (c) 2022-2023 Steve Jack
 *
 * MIT licence
 *
 * Notes
 *
 * The cryptography for the Japanese ID is probably wrong, but shouldn't be far off.
 *
 * The English translation of the specification for the Japanese ID is available at -
 * https://www.mlit.go.jp/koku/content/001582250.pdf
 *
 * There is a slight conflict in the specification over the tag length, 12 or 16?
 *
 *
 */

#pragma GCC diagnostic warning "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable" */

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <math.h>
#include <ctype.h>

#include "rid_capture.h"

#if VERIFY

#include <gcrypt.h>

static const int          key_len = 16, iv_len = 12, iv_fixed_len = 6, tag_len = 12,
                          plain_len  = 4 * ODID_MESSAGE_SIZE,
                          cipher_len = 4 * ODID_MESSAGE_SIZE;
static uint8_t            key[20], iv[20], cipher_text[128];
static uint64_t           cry_ctl_params[3];
static FILE              *debug_file = NULL;
static gcry_cipher_hd_t   aes_cipher_handle;

extern char               pass_s[], fail_s[];

/*
 *
 */

int init_crypto(uint8_t *_key,int _key_len,uint8_t *_iv,int _iv_len,
                FILE *debug) {

  gcry_error_t  cry_err;
  const char   *req_cry_ver = "1.8.0";

  debug_file = debug;

  //

  memset(iv,         0,sizeof(iv));
  memset(key,        0,sizeof(key));
  memset(cipher_text,0,sizeof(cipher_text));
  
  cry_ctl_params[0] = cipher_len;
  cry_ctl_params[1] =  0; // additional length
  cry_ctl_params[2] = 12; // tag length

  memcpy(key,_key,(_key_len < key_len)      ? _key_len: key_len);
  memcpy(iv, _iv, ( _iv_len < iv_fixed_len) ? _iv_len:  iv_fixed_len);

  if (!gcry_check_version(req_cry_ver)) {

    fprintf(stderr,"GNU crypo library version %s\n",gcry_check_version(NULL));

    return 2;
  }

  gcry_control(GCRYCTL_DISABLE_SECMEM,0);

  gcry_control(GCRYCTL_INITIALIZATION_FINISHED,0);

  if (cry_err = gcry_cipher_open(&aes_cipher_handle,GCRY_CIPHER_AES128,GCRY_CIPHER_MODE_CCM,GCRY_CIPHER_CBC_MAC)) {

    fprintf(stderr,"gcry_cipher_open(): %x %s\n",cry_err,gcry_strerror(cry_err));
  }

  /* The next three calls are done here to check for errors. */
  
  if (cry_err = gcry_cipher_setkey(aes_cipher_handle,key,key_len)) {

    fprintf(stderr,"gcry_cipher_setkey(): %x %s %d\n",cry_err,gcry_strerror(cry_err),key_len);
  }

  if (cry_err = gcry_cipher_setiv(aes_cipher_handle,iv,iv_len)) {

    fprintf(stderr,"gcry_cipher_setiv(): %x %s\n",cry_err,gcry_strerror(cry_err));
  }

  if (cry_err = gcry_cipher_ctl(aes_cipher_handle,GCRYCTL_SET_CCM_LENGTHS,&cry_ctl_params,sizeof(cry_ctl_params))) { 

    fprintf(stderr,"gcry_cipher_ctl(): %x %s\n",cry_err,gcry_strerror(cry_err));
  }

  return 0;
}

/*
 *
 */

int parse_auth(ODID_UAS_Data *UAS_data,ODID_MessagePack_encoded *encoded_data,struct UAV_RID *UAV) {

  int                          pass = 0, i, j, k, *auth_length= NULL;
  char                         text[64], *a;
  size_t                       res_len;
  uint8_t                     *sig = NULL, plain_text[128], cry_result[16], *u8, *auth_buffer = NULL;
  ODID_Message_encoded        *messages;
  ODID_Auth_encoded_page_zero *page_zero;
  gcry_error_t                 cry_err;
  static int                   call = 0;

  memset(cry_result,0,sizeof(cry_result));

  auth_length = &UAV->auth_length; 
  auth_buffer =  UAV->auth_buffer;
  
  messages    = (ODID_Message_encoded *) plain_text;
  page_zero   = &encoded_data->Messages[3].auth.page_zero;
  
  for (i = 0; i < ODID_AUTH_MAX_PAGES; ++i) {

    if (UAS_data->AuthValid[i]) {

      j = (i < 1) ? ODID_AUTH_PAGE_ZERO_DATA_SIZE:
                    ODID_AUTH_PAGE_NONZERO_DATA_SIZE;
      k = (i < 1) ? 0:
                    ODID_AUTH_PAGE_ZERO_DATA_SIZE + ((i - 1) * ODID_AUTH_PAGE_NONZERO_DATA_SIZE);

      memcpy(&auth_buffer[k],UAS_data->Auth[i].AuthData,j);

      if (*auth_length < (j + k)) {
        *auth_length = j + k;
      }
    }
  }

  if ((encoded_data->MsgPackSize > 3)&&
      (encoded_data->Messages[0].basicId.MessageType  == ODID_MESSAGETYPE_BASIC_ID)&&
      (encoded_data->Messages[1].basicId.MessageType  == ODID_MESSAGETYPE_BASIC_ID)&&
      (encoded_data->Messages[2].location.MessageType == ODID_MESSAGETYPE_LOCATION)&&
      (page_zero->MessageType                         == ODID_MESSAGETYPE_AUTH)&&
      (page_zero->AuthType                            == ODID_AUTH_MESSAGE_SET_SIGNATURE)) {

    /* Japanese ? */

    sig         = &page_zero->AuthData[1];
    res_len     = tag_len;
    
    memset(plain_text,0,sizeof(plain_text));
    memcpy(plain_text,encoded_data->Messages,plain_len);
    memset(&messages[3].auth.page_zero.AuthData[1],0,tag_len);

    /* We now have a copy of the four packed messages with the signature zeroed. */

    /* This is probably wrong. */

    /* The IV for Japanese RIDs consists of 6 fixed bytes follwed by the timestamp fields from
     * location and auth.page_zero.
     */
    
    u8        = (uint8_t *) &encoded_data->Messages[2].location.TimeStamp;
    iv[j = 6] = u8[0];
    iv[++j]   = u8[1]; 

    u8        = (uint8_t *) &encoded_data->Messages[3].auth.page_zero.Timestamp;
    iv[++j]   = u8[0];
    iv[++j]   = u8[1]; 
    iv[++j]   = u8[2];
    iv[++j]   = u8[3]; 

    cry_err = gcry_cipher_reset(aes_cipher_handle);
    cry_err = gcry_cipher_setkey(aes_cipher_handle,key,key_len);
    cry_err = gcry_cipher_setiv(aes_cipher_handle,iv,12);
    cry_err = gcry_cipher_ctl(aes_cipher_handle,GCRYCTL_SET_CCM_LENGTHS,&cry_ctl_params,sizeof(cry_ctl_params));

    cry_err = gcry_cipher_encrypt(aes_cipher_handle,cipher_text,cipher_len,plain_text,plain_len);
    cry_err = gcry_cipher_final(aes_cipher_handle);
    cry_err = gcry_cipher_gettag(aes_cipher_handle,cry_result,res_len);

    pass = (memcmp(sig,cry_result,tag_len) == 0) ? 1: 0;
    a    = (pass) ? pass_s: fail_s;

    sprintf(text,", \"Japanese ID check\" : \"%s\"",a);
    write_json(text);
    
    if (++call == 1) {
    
      dump("key",key,16);
      dump("iv",iv,12);
      dump("plaintext",plain_text,plain_len);
      dump("ciphertext",cipher_text,cipher_len);
      dump("expected tag",sig,tag_len);
      dump("calculated tag",cry_result,tag_len);
    }

  } else {

    if (*auth_length) {

      sprintf(text,", \"authentication\" : \"%s\"",printable_text(auth_buffer,*auth_length));
      write_json(text);
    }
  }
  
  return pass;
}

/*
 *
 */

void close_crypto() {

  gcry_cipher_close(aes_cipher_handle);

  return;
}

/*
 *
 */

#endif
