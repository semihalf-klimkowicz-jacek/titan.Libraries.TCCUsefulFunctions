///////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2000-2017 Ericsson Telecom AB
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Eclipse Public License v1.0
// which accompanies this distribution, and is available at
// http://www.eclipse.org/legal/epl-v10.html
///////////////////////////////////////////////////////////////////////////////
//
//  File:               TCCOpenSecurity.cc
//  Description:        TCC Useful Functions: Security Functions
//  Rev:                R30A
//  Prodnr:             CNL 113 472
//
///////////////////////////////////////////////////////////////////////////////
#include "TCCOpenSecurity_Functions.hh"

#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
#include <openssl/des.h>
#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#include <openssl/modes.h>
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */

namespace TCCOpenSecurity__Functions {


///////////////////////////////////////////////////////////////////////////////
//  Function: f__calculateRAND__oct
//
//  Purpose:
//    Compute random value
//
//  Parameters:
//      pl__length - *in* *integer* -  length of random value
//
//  Return Value:
//      random value - *out* *octetstring* -  random value
//
//  Errors:
//      -
//
//  Detailed description:
//      -
//
///////////////////////////////////////////////////////////////////////////////
OCTETSTRING  f__calculateRAND__oct(const INTEGER& pl__length)
{
  int rand_length = (int)pl__length;
  unsigned char rand_val[rand_length];
  RAND_bytes(rand_val, rand_length);

  return OCTETSTRING(rand_length, rand_val);
}


///////////////////////////////////////////////////////////////////////////////
//  Function: f__calculateSHA1
//
//  Purpose:
//    Compute SHA1 hash value
//
//  Parameters:
//      pszHashInput - *in* *charstring* -  input value to compute hash of
//
//  Return Value:
//      hashValue - *out* *charstring* -  hexa hash value of input
//
//  Errors:
//      -
//
//  Detailed description:
//      -
//
///////////////////////////////////////////////////////////////////////////////
CHARSTRING  f__calculateSHA1(const CHARSTRING& pszHashInput)
{
  unsigned char sha1[SHA_DIGEST_LENGTH];
  SHA1((const unsigned char*)(const char *)pszHashInput,pszHashInput.lengthof(),sha1);

  return oct2str(OCTETSTRING(SHA_DIGEST_LENGTH,sha1));
}

///////////////////////////////////////////////////////////////////////////////
//  Function: f__calculateSHA1__oct
//
//  Purpose:
//    Compute SHA1 hash value and return in octetstring
//
//  Parameters:
//      pszHashInput - *in* *octetstring* -  input value to compute hash of
//
//  Return Value:
//      hashValue - *out* *octetstring* -  hash value of input in octetstring
//
//  Errors:
//      -
//
//  Detailed description:
//      -
//
///////////////////////////////////////////////////////////////////////////////
OCTETSTRING  f__calculateSHA1__oct(const OCTETSTRING& pszHashInput)
{
  unsigned char sha1[SHA_DIGEST_LENGTH];
  SHA1((const unsigned char*)pszHashInput,pszHashInput.lengthof(),sha1);

  return OCTETSTRING(SHA_DIGEST_LENGTH,sha1);
}


///////////////////////////////////////////////////////////////////////////////
//  Function: f__calculateHMACMD5
//
//  Purpose:
//      Calculate the HMAC MD5 value of a message with specified 64 bit key.
//
//  Parameters:
//      msg - *in* *octetstring* - message to be hashed
//      key - *in* *OCT_64*      - 64 bit key of the hash function
//
//  Return Value:
//      octetstring - Hash value (16 octet - 128 bit)
//
//  Errors:
//      -
//
//  Detailed description:
//      - (should be kept because of backward compatibility reasons)
//      - HMAC() is an openssl specific function, should be found under openssl/hmac.h
//      - key can only be 64 bit (any other case please use f_calculate_HMAC_MD5)
//      - the length of generated hash value can only be 128 bit (any other case please use f_calculate_HMAC_MD5)
//
///////////////////////////////////////////////////////////////////////////////
OCTETSTRING f__calculateHMACMD5(const OCTETSTRING& msg, const OCT__64& key)
{
  unsigned char Response[16];
  int msglen = msg.lengthof();

  HMAC(EVP_md5(), key, 64, msg, msglen, Response, NULL);

  return OCTETSTRING(16, (const unsigned char *)Response);
}

///////////////////////////////////////////////////////////////////////////////
//  Function: f__calculate__HMAC__MD5
//
//  Purpose:
//      Calculate the HMAC MD5 value of a message with specified key.
//
//  Parameters:
//      pl_key - *in* *octetstring*   - key of the hash function
//      pl_input - *in* *octetstring* - message to be hashed
//      pl_length - *in* *integer*    - length of the output hash value (should be 16 in most of the cases)
//
//  Return Value:
//      octetstring - Hash value
//
//  Errors:
//      -
//
//  Detailed description:
//      - HMAC() is an openssl specific function, should be found under openssl/hmac.h
//
///////////////////////////////////////////////////////////////////////////////
OCTETSTRING f__calculate__HMAC__MD5(const OCTETSTRING& pl_key,const OCTETSTRING& pl_input,const INTEGER& pl_length)
{
  unsigned int out_length;
  unsigned char output[EVP_MAX_MD_SIZE];
  HMAC(EVP_md5(), pl_key, (size_t) pl_key.lengthof(), pl_input, (size_t) pl_input.lengthof(), output, &out_length);

  return OCTETSTRING(pl_length, output);
}

///////////////////////////////////////////////////////////////////////////////
//  Function: f__calculate__HMAC__SHA1
//
//  Purpose:
//      Calculate the HMAC SHA1 value of a message with specified key.
//
//  Parameters:
//      pl_key - *in* *octetstring*   - key of the hash function
//      pl_input - *in* *octetstring* - message to be hashed
//      pl_length - *in* *integer*    - length of the output hash value (should be 16 in most of the cases)
//
//  Return Value:
//      octetstring - Hash value
//
//  Errors:
//      -
//
//  Detailed description:
//      - HMAC() is an openssl specific function, should be found under openssl/hmac.h
//
///////////////////////////////////////////////////////////////////////////////
OCTETSTRING f__calculate__HMAC__SHA1(const OCTETSTRING& pl_key,const OCTETSTRING& pl_input,const INTEGER& pl_length)
{
  unsigned int out_length;
  unsigned char output[EVP_MAX_MD_SIZE];
  HMAC(EVP_sha1(), pl_key, (size_t) pl_key.lengthof(), pl_input, (size_t) pl_input.lengthof(), output, &out_length);

  return OCTETSTRING(pl_length, output);
}

///////////////////////////////////////////////////////////////////////////////
//  Function: f__calculate__HMAC__SHA256
//
//  Purpose:
//      Calculate the HMAC SHA256 value of a message with specified key.
//
//  Parameters:
//      pl_key - *in* *octetstring*   - key of the hash function
//      pl_input - *in* *octetstring* - message to be hashed
//      pl_length - *in* *integer*    - length of the output hash value (should be 32 in most of the cases)
//
//  Return Value:
//      octetstring - Hash value
//
//  Errors:
//      -
//
//  Detailed description:
//      - HMAC() is an openssl specific function, should be found under openssl/hmac.h
//
///////////////////////////////////////////////////////////////////////////////
OCTETSTRING f__calculate__HMAC__SHA256(const OCTETSTRING& pl_key,const OCTETSTRING& pl_input,const INTEGER& pl_length)
{
  unsigned int out_length;
  unsigned char output[EVP_MAX_MD_SIZE];
  HMAC(EVP_sha256(), pl_key, (size_t) pl_key.lengthof(), pl_input, (size_t) pl_input.lengthof(), output, &out_length);

  return OCTETSTRING(pl_length, output);
}


///////////////////////////////////////////////////////////////////////////////
//  Function: f__AES__CBC__128__Encrypt__OpenSSL
//
//  Purpose: Calculate AES 128 CBC encrypted value
//
//  Parameters:
//          p__key       - *in* *octetstring*   - Key
//          p__iv        - *in* *octetstring*   - Initialiazation Vector
//          p__data      - *in* *octetstring*   - Data
//
//  Return Value:
//         octetstring - encrypted value
//
//  Errors:
//      -
//
//  Detailed description:
//      -
//
///////////////////////////////////////////////////////////////////////////////
OCTETSTRING f__AES__CBC__128__Encrypt__OpenSSL (const OCTETSTRING& p_key,const OCTETSTRING& p_iv,const OCTETSTRING& p_data)
{

  const unsigned char* key=(const unsigned char*)p_key;
  const unsigned char* iv=(const unsigned char*)p_iv;
  size_t data_len = p_data.lengthof();
  const unsigned char* data=(const unsigned char*)p_data;
  size_t iv_len = p_iv.lengthof();

  AES_KEY enc_key;
  unsigned char enc_data[data_len];
  unsigned char k_iv[iv_len];

  memcpy(k_iv,iv,iv_len);

  AES_set_encrypt_key(key, 128, &enc_key);

  AES_cbc_encrypt(data, enc_data,
    data_len, &enc_key,
    k_iv, AES_ENCRYPT);

  return OCTETSTRING(data_len, enc_data);
}


///////////////////////////////////////////////////////////////////////////////
//  Function: f__AES__CBC__128__Decrypt__OpenSSL
//
//  Purpose: Dectrypts AES 128 CBC encrypted data
//
//  Parameters:
//          p__key       - *in* *octetstring*   - Key
//          p__iv        - *in* *octetstring*   - Initialiazation Vector
//          p__data      - *in* *octetstring*   - Encrypted Value
//
//  Return Value:
//         octetstring - decrypted original data
//
//  Errors:
//      -
//
//  Detailed description:
//      -
//
///////////////////////////////////////////////////////////////////////////////
OCTETSTRING f__AES__CBC__128__Decrypt__OpenSSL (const OCTETSTRING& p_key,const OCTETSTRING& p_iv,const OCTETSTRING& p_data)
{

  const unsigned char* key=(const unsigned char*)p_key;
  const unsigned char* iv=(const unsigned char*)p_iv;
  size_t data_len = p_data.lengthof();
  const unsigned char* data=(const unsigned char*)p_data;
  size_t iv_len = p_iv.lengthof();

  AES_KEY dec_key;
  unsigned char dec_data[data_len];
  unsigned char k_iv[iv_len];

  memcpy(k_iv,iv,iv_len);

  AES_set_decrypt_key(key, 128, &dec_key);

  AES_cbc_encrypt(data, dec_data,
    data_len, &dec_key,
    k_iv, AES_DECRYPT);

  return OCTETSTRING(data_len, dec_data);
}

///////////////////////////////////////////////////////////////////////////////
//  Function: f__AES__CBC__Encrypt__OpenSSL
//
//  Purpose: Calculate AES 128 CBC encrypted value with arbitrary key length
//
//  Parameters:
//          p__key       - *in* *octetstring*   - Key
//          p__iv        - *in* *octetstring*   - Initialiazation Vector
//          p__data      - *in* *octetstring*   - Data
//
//  Return Value:
//         octetstring - encrypted value
//
//  Errors:
//      -
//
//  Detailed description:
//      -
//
///////////////////////////////////////////////////////////////////////////////
OCTETSTRING f__AES__CBC__Encrypt__OpenSSL (const OCTETSTRING& p_key,const OCTETSTRING& p_iv,const OCTETSTRING& p_data)
{
  const unsigned char* key=(const unsigned char*)p_key;
  const int key_len_bit = p_key.lengthof() * 8;
  const unsigned char* iv=(const unsigned char*)p_iv;
  size_t data_len = p_data.lengthof();
  const unsigned char* data=(const unsigned char*)p_data;
  size_t iv_len = p_iv.lengthof();

  AES_KEY enc_key;
  unsigned char enc_data[data_len];
  unsigned char k_iv[iv_len];

  memcpy(k_iv,iv,iv_len);

  AES_set_encrypt_key(key, key_len_bit, &enc_key);

  AES_cbc_encrypt(data, enc_data,
    data_len, &enc_key,
    k_iv, AES_ENCRYPT);

  return OCTETSTRING(data_len, enc_data);
}


///////////////////////////////////////////////////////////////////////////////
//  Function: f__AES__CBC__Decrypt__OpenSSL
//
//  Purpose: Dectrypts AES CBC encrypted data with arbitrary key length
//
//  Parameters:
//          p__key       - *in* *octetstring*   - Key
//          p__iv        - *in* *octetstring*   - Initialiazation Vector
//          p__data      - *in* *octetstring*   - Encrypted Value
//
//  Return Value:
//         octetstring - decrypted original data
//
//  Errors:
//      -
//
//  Detailed description:
//      -
//
///////////////////////////////////////////////////////////////////////////////
OCTETSTRING f__AES__CBC__Decrypt__OpenSSL (const OCTETSTRING& p_key,const OCTETSTRING& p_iv,const OCTETSTRING& p_data)
{

  const unsigned char* key=(const unsigned char*)p_key;
  const int key_len_bit = p_key.lengthof() * 8;
  const unsigned char* iv=(const unsigned char*)p_iv;
  size_t data_len = p_data.lengthof();
  const unsigned char* data=(const unsigned char*)p_data;
  size_t iv_len = p_iv.lengthof();

  AES_KEY dec_key;
  unsigned char dec_data[data_len];
  unsigned char k_iv[iv_len];

  memcpy(k_iv,iv,iv_len);

  AES_set_decrypt_key(key, key_len_bit, &dec_key);

  AES_cbc_encrypt(data, dec_data,
    data_len, &dec_key,
    k_iv, AES_DECRYPT);

  return OCTETSTRING(data_len, dec_data);
}


///////////////////////////////////////////////////////////////////////////////
//  Function: ef__3DES__ECB__Encrypt
//
//  Purpose: Encrypts data using 3DES algorithm in ECB mode.
//
//  Parameters:
//          pl__data    - *in* *octetstring*   - Data to be encrypted
//          pl__key     - *in* *octetstring*   - Key
//
//  Return Value:
//         octetstring - encrypted data
//
//  Errors:
//      -
//
//  Detailed description:
//      -
//
///////////////////////////////////////////////////////////////////////////////
OCTETSTRING ef__3DES__ECB__Encrypt (const OCTETSTRING& pl__data, const OCTETSTRING& pl__key, const BOOLEAN& pl__use__padding)
{
  if(pl__data.lengthof()==0){
    return OCTETSTRING(0,NULL);
  }

  int outl = 0;
  int position = 0;
  OCTETSTRING ret_val=OCTETSTRING(0,NULL);
   unsigned char* outbuf=NULL;
  const unsigned char* data= (const unsigned char*)pl__data;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX_init(ctx);
#else
  EVP_CIPHER_CTX ctx;
  EVP_CIPHER_CTX_init(&ctx);
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  if(EVP_EncryptInit_ex(ctx, EVP_des_ede3_ecb(), NULL, pl__key, NULL))
  {
    int block_size = EVP_CIPHER_CTX_block_size(ctx);
     if(!pl__use__padding) {  // the padding is used by default
      EVP_CIPHER_CTX_set_padding(ctx,0);
#else
  if(EVP_EncryptInit_ex(&ctx, EVP_des_ede3_ecb(), NULL, pl__key, NULL))
  {
    int block_size = EVP_CIPHER_CTX_block_size(&ctx);
     if(!pl__use__padding) {  // the padding is used by default
      EVP_CIPHER_CTX_set_padding(&ctx,0);
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
      if(pl__data.lengthof()%block_size){
        TTCN_warning("ef_3DES_ECB_Encrypt: The length of the pl_data should be n * %d (the block size) if padding is not used.", block_size);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        EVP_CIPHER_CTX_free(ctx);
#else
        EVP_CIPHER_CTX_cleanup(&ctx);
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */

        return OCTETSTRING(0,NULL);
      }
    }
    if((outbuf = (unsigned char*)Malloc(pl__data.lengthof() + block_size)) != NULL)
    {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
      if(!EVP_EncryptUpdate(ctx, outbuf, &outl, data, pl__data.lengthof())){
#else
      if(!EVP_EncryptUpdate(&ctx, outbuf, &outl, data, pl__data.lengthof())){
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
        TTCN_warning("ef_3DES_ECB_Encrypt: EVP_EncryptUpdate failed.");
        Free(outbuf);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        EVP_CIPHER_CTX_free(ctx);
#else
        EVP_CIPHER_CTX_cleanup(&ctx);
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
        return OCTETSTRING(0,NULL);
      }
      position = outl;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
      if(!EVP_EncryptFinal_ex(ctx, &outbuf[position], &outl)){
#else
      if(!EVP_EncryptFinal_ex(&ctx, &outbuf[position], &outl)){
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
        TTCN_warning("ef_3DES_ECB_Encrypt: EVP_EncryptFinal_ex failed.");
        Free(outbuf);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        EVP_CIPHER_CTX_free(ctx);
#else
        EVP_CIPHER_CTX_cleanup(&ctx);
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
        return OCTETSTRING(0,NULL);
      }

      position += outl;
      ret_val=OCTETSTRING(position, outbuf);
      Free(outbuf);
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    EVP_CIPHER_CTX_free(ctx);
#else
    EVP_CIPHER_CTX_cleanup(&ctx);
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */

  } else {
        TTCN_warning("ef_3DES_ECB_Encrypt: EVP_EncryptInit_ex failed.");
        return OCTETSTRING(0,NULL);
  }


  return ret_val;

}

///////////////////////////////////////////////////////////////////////////////
//  Function: ef__3DES__ECB__Decrypt
//
//  Purpose:  Dectrypts 3DES ECB encrypted data.
//
//  Parameters:
//          pl__data      - *in* *octetstring*   - Encrytped data
//          pl__key       - *in* *octetstring*   - Key
//
//  Return Value:
//         octetstring - decrypted data
//
//  Errors:
//      -
//
//  Detailed description:
//      -
//
///////////////////////////////////////////////////////////////////////////////
OCTETSTRING ef__3DES__ECB__Decrypt (const OCTETSTRING& pl__data, const OCTETSTRING& pl__key, const BOOLEAN& pl__use__padding)
{
  if(pl__data.lengthof()==0){
    return OCTETSTRING(0,NULL);
  }
  int outl = 0;
  int position = 0;
  OCTETSTRING ret_val=OCTETSTRING(0,NULL);
   unsigned char* outbuf=NULL;
  const unsigned char* data= (const unsigned char*)pl__data;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX_init(ctx);
#else
  EVP_CIPHER_CTX ctx;
  EVP_CIPHER_CTX_init(&ctx);
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  if(EVP_DecryptInit_ex(ctx, EVP_des_ede3_ecb(), NULL, pl__key, NULL))
  {
    int block_size = EVP_CIPHER_CTX_block_size(ctx);
#else
  if(EVP_DecryptInit_ex(&ctx, EVP_des_ede3_ecb(), NULL, pl__key, NULL))
  {
    int block_size = EVP_CIPHER_CTX_block_size(&ctx);
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
    if(pl__data.lengthof()%block_size){
      TTCN_warning("ef_3DES_ECB_Decrypt: The length of the pl_data should be n * %d (the block size)!", block_size);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
      EVP_CIPHER_CTX_free(ctx);
#else
      EVP_CIPHER_CTX_cleanup(&ctx);
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
      return OCTETSTRING(0,NULL);
    }
     if(!pl__use__padding) {  // the padding is used by default
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
      EVP_CIPHER_CTX_set_padding(ctx,0);
#else
      EVP_CIPHER_CTX_set_padding(&ctx,0);
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
    }
    if((outbuf = (unsigned char*)Malloc(pl__data.lengthof() + block_size)) != NULL)
    {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
      if(!EVP_DecryptUpdate(ctx, outbuf, &outl, data, pl__data.lengthof())){
#else
      if(!EVP_DecryptUpdate(&ctx, outbuf, &outl, data, pl__data.lengthof())){
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
        TTCN_warning("ef_3DES_ECB_Decrypt: EVP_DecryptUpdate failed.");
        Free(outbuf);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        EVP_CIPHER_CTX_free(ctx);
#else
        EVP_CIPHER_CTX_cleanup(&ctx);
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
        return OCTETSTRING(0,NULL);
      }
      position = outl;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
      if(!EVP_DecryptFinal_ex(ctx, &outbuf[position], &outl)){
#else
      if(!EVP_DecryptFinal_ex(&ctx, &outbuf[position], &outl)){
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
        TTCN_warning("ef_3DES_ECB_Decrypt: EVP_DecryptFinal_ex failed.");
        Free(outbuf);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        EVP_CIPHER_CTX_free(ctx);
#else
        EVP_CIPHER_CTX_cleanup(&ctx);
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
        return OCTETSTRING(0,NULL);
      }

      position += outl;
      ret_val=OCTETSTRING(position, outbuf);
      Free(outbuf);
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    EVP_CIPHER_CTX_free(ctx);
#else
    EVP_CIPHER_CTX_cleanup(&ctx);
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */

  } else {
        TTCN_warning("ef_3DES_ECB_Decrypt: EVP_DecryptInit_ex failed.");
        return OCTETSTRING(0,NULL);
  }


  return ret_val;

}



///////////////////////////////////////////////////////////////////////////////
//  Function: ef__3DES__CBC__Encrypt
//
//  Purpose: Encrypts data using TripleDES algorithm in CBC mode.
//
//  Parameters:
//          pl__data      - *in* *octetstring*   - Data to be encrypted
//          pl__key       - *in* *octetstring*   - Key
//          pl__iv        - *in* *octetstring*   - Initialiazation Vector
//
//  Return Value:
//         octetstring - decrypted original data
//
//  Errors:
//      -
//
//  Detailed description:
//      -
//
///////////////////////////////////////////////////////////////////////////////
OCTETSTRING ef__3DES__CBC__Encrypt (const OCTETSTRING& pl__data, const OCTETSTRING& pl__key, const OCTETSTRING& pl__iv, const BOOLEAN& pl__use__padding)
{
  if(pl__data.lengthof()==0){
    return OCTETSTRING(0,NULL);
  }
  int outl = 0;
  int position = 0;
  OCTETSTRING ret_val=OCTETSTRING(0,NULL);
   unsigned char* outbuf=NULL;
  const unsigned char* data= (const unsigned char*)pl__data;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX_init(ctx);

  if(EVP_EncryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, pl__key, pl__iv))
  {
    int block_size = EVP_CIPHER_CTX_block_size(ctx);
     if(!pl__use__padding) {  // the padding is used by default
      EVP_CIPHER_CTX_set_padding(ctx,0);
#else
  EVP_CIPHER_CTX ctx;
  EVP_CIPHER_CTX_init(&ctx);

  if(EVP_EncryptInit_ex(&ctx, EVP_des_ede3_cbc(), NULL, pl__key, pl__iv))
  {
    int block_size = EVP_CIPHER_CTX_block_size(&ctx);
     if(!pl__use__padding) {  // the padding is used by default
      EVP_CIPHER_CTX_set_padding(&ctx,0);
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
      if(pl__data.lengthof()%block_size){
        TTCN_warning("ef_3DES_CBC_Encrypt: The length of the pl_data should be n * %d (the block size) if padding is not used.", block_size);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        EVP_CIPHER_CTX_free(ctx);
#else
        EVP_CIPHER_CTX_cleanup(&ctx);
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
        return OCTETSTRING(0,NULL);
      }
    }
    if((outbuf = (unsigned char*)Malloc(pl__data.lengthof() + block_size)) != NULL)
    {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
      if(!EVP_EncryptUpdate(ctx, outbuf, &outl, data, pl__data.lengthof())){
#else
      if(!EVP_EncryptUpdate(&ctx, outbuf, &outl, data, pl__data.lengthof())){
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
        TTCN_warning("ef_3DES_CBC_Encrypt: EVP_EncryptUpdate failed.");
        Free(outbuf);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        EVP_CIPHER_CTX_free(ctx);
#else
        EVP_CIPHER_CTX_cleanup(&ctx);
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
        return OCTETSTRING(0,NULL);
      }

      position = outl;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
      if(!EVP_EncryptFinal_ex(ctx, &outbuf[position], &outl)){
#else
      if(!EVP_EncryptFinal_ex(&ctx, &outbuf[position], &outl)){
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
        TTCN_warning("ef_3DES_CBC_Encrypt: EVP_EncryptFinal_ex failed.");
        Free(outbuf);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        EVP_CIPHER_CTX_free(ctx);
#else
        EVP_CIPHER_CTX_cleanup(&ctx);
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
        return OCTETSTRING(0,NULL);
      }

      position += outl;
    }

    ret_val=OCTETSTRING(position, outbuf);
    Free(outbuf);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    EVP_CIPHER_CTX_free(ctx);
#else
    EVP_CIPHER_CTX_cleanup(&ctx);
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */

  } else {
        TTCN_warning("ef_3DES_CBC_Encrypt: EVP_EncryptInit_ex failed.");
        return OCTETSTRING(0,NULL);
  }


  return ret_val;

}

///////////////////////////////////////////////////////////////////////////////
//  Function: f__3DES__CBC__Decrypt
//
//  Purpose: Decrypting TripleDES encypted data.
//
//  Parameters:
//          pl__data      - *in* *octetstring*   - Encrypted Value
//          pl__key       - *in* *octetstring*   - Key
//          pl__iv        - *in* *octetstring*   - Initialiazation Vector
//
//  Return Value:
//         octetstring - encrypted value
//
//  Errors:
//      -
//
//  Detailed description:
//      -
//
///////////////////////////////////////////////////////////////////////////////
OCTETSTRING ef__3DES__CBC__Decrypt (const OCTETSTRING& pl__data, const OCTETSTRING& pl__key, const OCTETSTRING& pl__iv, const BOOLEAN& pl__use__padding)
{
  if(pl__data.lengthof()==0){
    return OCTETSTRING(0,NULL);
  }
  int outl = 0;
  int position = 0;
  OCTETSTRING ret_val=OCTETSTRING(0,NULL);
   unsigned char* outbuf=NULL;
  const unsigned char* data= (const unsigned char*)pl__data;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX_init(ctx);

  if(EVP_DecryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, pl__key, pl__iv))
  {
    int block_size = EVP_CIPHER_CTX_block_size(ctx);
#else
  EVP_CIPHER_CTX ctx;
  EVP_CIPHER_CTX_init(&ctx);

  if(EVP_DecryptInit_ex(&ctx, EVP_des_ede3_cbc(), NULL, pl__key, pl__iv))
  {
    int block_size = EVP_CIPHER_CTX_block_size(&ctx);
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
    if(pl__data.lengthof()%block_size){
      TTCN_warning("ef__3DES__CBC__Decrypt: The length of the pl_data should be n * %d (the block size)!", block_size);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        EVP_CIPHER_CTX_free(ctx);
#else
        EVP_CIPHER_CTX_cleanup(&ctx);
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
      return OCTETSTRING(0,NULL);
    }
     if(!pl__use__padding) {  // the padding is used by default
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
      EVP_CIPHER_CTX_set_padding(ctx,0);
#else
      EVP_CIPHER_CTX_set_padding(&ctx,0);
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
    }
    if((outbuf = (unsigned char*)Malloc(pl__data.lengthof() + block_size)) != NULL)
    {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
      if(!EVP_DecryptUpdate(ctx, outbuf, &outl, data, pl__data.lengthof())){
#else
      if(!EVP_DecryptUpdate(&ctx, outbuf, &outl, data, pl__data.lengthof())){
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
        TTCN_warning("ef_3DES_CBC_Decrypt: EVP_DecryptUpdate failed.");
        Free(outbuf);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        EVP_CIPHER_CTX_free(ctx);
#else
        EVP_CIPHER_CTX_cleanup(&ctx);
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
        return OCTETSTRING(0,NULL);
      }
;
      position = outl;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
      if(!EVP_DecryptFinal_ex(ctx, &outbuf[position], &outl)){
#else
      if(!EVP_DecryptFinal_ex(&ctx, &outbuf[position], &outl)){
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
        TTCN_warning("ef_3DES_ECB_Decrypt: EVP_DecryptFinal_ex failed.");
        Free(outbuf);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        EVP_CIPHER_CTX_free(ctx);
#else
        EVP_CIPHER_CTX_cleanup(&ctx);
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
        return OCTETSTRING(0,NULL);
      }
      position += outl;
      ret_val=OCTETSTRING(position, outbuf);
      Free(outbuf);
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    EVP_CIPHER_CTX_free(ctx);
#else
    EVP_CIPHER_CTX_cleanup(&ctx);
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */

  } else {
        TTCN_warning("ef_3DES_CBC_Decrypt: EVP_DecryptInit_ex failed.");
        return OCTETSTRING(0,NULL);
  }


  return ret_val;

}


///////////////////////////////////////////////////////////////////////////////
//  Function: ef_Calculate__AES__XCBC__128
//
//  Purpose: Calculates the AES XCBC value of the data with a 128 bit key.
//
//  Parameters:
//          pl__data       - *in* *octetstring*   - Data
//          pl__key        - *in* *octetstring*   - Key
//          pl__out__length - *in* *integer*       - Length of the output
//
//  Return Value:
//         octetstring - AES XCBC value
//
//  Errors:
//      -
//
//  Detailed description:
//      AES XCBC generates a 16 byte long value which can be truncated
//      to a length given in pl__out__length.
//
///////////////////////////////////////////////////////////////////////////////
OCTETSTRING ef__Calculate__AES__XCBC__128 (const OCTETSTRING& pl__data, const OCTETSTRING& pl__key, const INTEGER& pl__out__length)
{
  const int data_length = pl__data.lengthof();
  const unsigned char* data = (const unsigned char*)pl__data;
  const int block_size = 16;
  int outl;

  unsigned char key1[block_size] = { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };
  unsigned char key2[block_size] = { 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02 };
  unsigned char key3[block_size] = { 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03 };
  unsigned char e[block_size] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX_init(ctx);

  EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, pl__key, NULL);
  EVP_EncryptUpdate(ctx, key1, &outl, key1, block_size);
  EVP_CIPHER_CTX_free(ctx);

  EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, pl__key, NULL);
  EVP_EncryptUpdate(ctx, key2, &outl, key2, block_size);
  EVP_CIPHER_CTX_free(ctx);

  EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, pl__key, NULL);
  EVP_EncryptUpdate(ctx, key3, &outl, key3, block_size);
  EVP_CIPHER_CTX_free(ctx);

  if(EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key1, NULL))
#else
  EVP_CIPHER_CTX ctx;
  EVP_CIPHER_CTX_init(&ctx);

  EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, pl__key, NULL);
  EVP_EncryptUpdate(&ctx, key1, &outl, key1, block_size);
  EVP_CIPHER_CTX_cleanup(&ctx);

  EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, pl__key, NULL);
  EVP_EncryptUpdate(&ctx, key2, &outl, key2, block_size);
  EVP_CIPHER_CTX_cleanup(&ctx);

  EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, pl__key, NULL);
  EVP_EncryptUpdate(&ctx, key3, &outl, key3, block_size);
  EVP_CIPHER_CTX_cleanup(&ctx);

  if(EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, key1, NULL))
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
  {
    for(int i = 0; i < data_length - block_size; i += block_size)
    {
      for(int j = 0; j < block_size; j++)
      {
        e[j] ^= data[i+j];
      }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
      EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key1, NULL);
      EVP_EncryptUpdate(ctx, e, &outl, e, block_size);
      EVP_CIPHER_CTX_free(ctx);
#else
      EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, key1, NULL);
      EVP_EncryptUpdate(&ctx, e, &outl, e, block_size);
      EVP_CIPHER_CTX_cleanup(&ctx);
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
    }

    int last_block_length = data_length % block_size;

    if((last_block_length == 0) && (data_length != 0))
    {
      for(int i = 0; i < block_size; i++)
      {
        e[i] = data[data_length - block_size + i] ^ e[i] ^ key2[i];
      }
    } else {
      int i = 0;

      while(i < last_block_length)
      {
        e[i] = data[data_length - last_block_length + i] ^ e[i] ^ key3[i];
        i++;
      }

      e[i] = 0x80 ^ e[i] ^ key3[i];
      i++;


      while(i < block_size)
      {
        e[i] ^= key3[i];
        i++;
      }

    }
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key1, NULL);
    EVP_EncryptUpdate(ctx, e, &outl, e, block_size);
    EVP_CIPHER_CTX_free(ctx);
#else
    EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, key1, NULL);
    EVP_EncryptUpdate(&ctx, e, &outl, e, block_size);
    EVP_CIPHER_CTX_cleanup(&ctx);
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */

    return OCTETSTRING(pl__out__length, (const unsigned char*)e);

  }
  return OCTETSTRING(0,NULL);
}


///////////////////////////////////////////////////////////////////////////////
//  Function: ef_DH_generate_private_public_keys
//
//  Purpose: Generates public and private keys (this party).
//
//  Parameters:
//          pl__keyLength - *in* *integer*          - Key length (bytes)
//          pl__pubkey    - *inout* *octetstring*   - Public key (other party)
//          pl__privkey   - *inout* *octetstring*   - Private key (this party)
//
//  Return Value:
//         octetstring - DH shared secret
//
//  Errors:
//      -
//
//  Detailed description:
//      Computes the shared secret from the originating side's private key and
//      the public key of the responding side as described in DH group 1, 2 and 14.
//      Keys must be either 96, 128 or 256 bytes long.
//
///////////////////////////////////////////////////////////////////////////////
INTEGER ef__DH__generate__private__public__keys (const INTEGER& pl__keyLength, OCTETSTRING& pl__pubkey, OCTETSTRING& pl__privkey)
{
  int key_length = (int)pl__keyLength;

  const char* prime_768  = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF";

  const char* prime_1024 = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF";

  const char* prime_2048 = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

  DH* dh = DH_new();

  BIGNUM* prime = BN_new();
  switch(key_length)
  {
    case  96: BN_hex2bn(&prime, prime_768);  break;
    case 128: BN_hex2bn(&prime, prime_1024); break;
    case 256: BN_hex2bn(&prime, prime_2048); break;
    default:
    {
      DH_free(dh);
      return INTEGER(0);
    }
  }

  const char* generator = "2";
  BIGNUM* gen = BN_new();
  BN_hex2bn(&gen, generator);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  DH_set0_pqg(dh, prime, NULL, gen);
#else
  dh->p = prime;
  dh->g = gen;
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */

  DH_generate_key(dh);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  const BIGNUM *dh_pub_key, *dh_priv_key;
  DH_get0_key(dh, &dh_pub_key, &dh_priv_key);
  int pub_len = BN_num_bytes(dh_pub_key);
#else
  int pub_len = BN_num_bytes(dh->pub_key);
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */

  unsigned char* pub_key = (unsigned char*)Malloc(pub_len * sizeof(unsigned char));
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  pub_len = BN_bn2bin(dh_pub_key, pub_key);
#else
  pub_len = BN_bn2bin(dh->pub_key, pub_key);
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */

  if (key_length-pub_len > 0)
  {pl__pubkey =  int2oct(0,key_length-pub_len) + OCTETSTRING(pub_len, pub_key);}
  else
  {pl__pubkey =  OCTETSTRING(key_length, pub_key);}
  Free(pub_key);

  if (pub_len <= 0)
  {
      DH_free(dh);
      return INTEGER(0);
  }


#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  int priv_len = BN_num_bytes(dh_priv_key);
#else
  int priv_len = BN_num_bytes(dh->priv_key);
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */

  unsigned char* priv_key = (unsigned char*)Malloc(priv_len * sizeof(unsigned char));
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  priv_len = BN_bn2bin(dh_priv_key, priv_key);
#else
  priv_len = BN_bn2bin(dh->priv_key, priv_key);
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */

  if (key_length-priv_len > 0)
  {pl__privkey =  int2oct(0,key_length-priv_len) + OCTETSTRING(priv_len, priv_key);}
  else
  {pl__privkey =  OCTETSTRING(key_length, priv_key);}
  Free(priv_key);

  if (priv_len <= 0)
  {
      DH_free(dh);
      return INTEGER(0);
  }

  DH_free(dh);
  return INTEGER(1);
}

///////////////////////////////////////////////////////////////////////////////
//  Function: ef_DH_shared_secret
//
//  Purpose: Calculates the shared secret from the given public and private keys.
//
//  Parameters:
//          pl__pubkey    - *in* *octetstring*   - Public key (other party)
//          pl__privkey   - *in* *octetstring*   - Private key (this party)
//
//  Return Value:
//         octetstring - DH shared secret
//
//  Errors:
//      -
//
//  Detailed description:
//      Computes the shared secret from the originating side's private key and
//      the public key of the responding side as described in DH group 1, 2 and 14.
//      Keys must be either 96, 128 or 256 bytes long.
//
///////////////////////////////////////////////////////////////////////////////
OCTETSTRING ef__DH__shared__secret (const OCTETSTRING& pl__pubkey, const OCTETSTRING& pl__privkey)
{
  int key_length = pl__pubkey.lengthof();
  unsigned char shared_secret[key_length];

  const char* prime_768  = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF";

  const char* prime_1024 = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF";

  const char* prime_2048 = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

  DH* dh = DH_new();

  BIGNUM* prime = BN_new();
  switch(key_length)
  {
    case  96: BN_hex2bn(&prime, prime_768);  break;
    case 128: BN_hex2bn(&prime, prime_1024); break;
    case 256: BN_hex2bn(&prime, prime_2048); break;
    default:
    {
      DH_free(dh);
      return OCTETSTRING(0, NULL);
    }
  }

  const char* generator = "2";
  BIGNUM* gen = BN_new();
  BN_hex2bn(&gen, generator);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  DH_set0_pqg(dh, prime, NULL, gen);
#else
  dh->p = prime;
  dh->g = gen;
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */

  BIGNUM* priv_key = BN_new();
  BN_bin2bn((const unsigned char*)pl__privkey, key_length, priv_key);

  BIGNUM* pub_key = BN_new();
  BN_bin2bn((const unsigned char*)pl__pubkey, key_length, pub_key);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  DH_set0_key(dh, pub_key, priv_key);
#else
  dh->priv_key = priv_key;
  dh->pub_key = pub_key;
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */

  if(DH_compute_key(shared_secret, pub_key, dh))
  {
    DH_free(dh);
    return OCTETSTRING(key_length, shared_secret);
  }

  DH_free(dh);
  return OCTETSTRING(0, NULL);

}


///////////////////////////////////////////////////////////////////////////////
//  Function: f_AES_ECB_128_Encrypt_OpenSSL
//
//  Purpose: Calculate AES 128 ECB encrypted value
//
//  Parameters:
//          p_key       - *in* *octetstring*   - Key
//          p_data      - *in* *octetstring*   - Data
//
//  Return Value:
//         octetstring - encrypted value
//
//  Errors:
//      -
//
//  Detailed description:
//      -
//
///////////////////////////////////////////////////////////////////////////////
OCTETSTRING f__AES__ECB__128__Encrypt__OpenSSL (const OCTETSTRING& p_key,const OCTETSTRING& p_data)
{
  if(p_key.lengthof()!=16){
    TTCN_error("f_AES_EBC_128_Encrypt_OpenSSL: The length of the key should be 16 instead of %d",p_key.lengthof() );
  }
  const unsigned char* data=(const unsigned char*)p_data;
  int data_len = p_data.lengthof();

  int outbuf_len=data_len+AES_BLOCK_SIZE;

  unsigned char* outbuf=(unsigned char*)Malloc(outbuf_len * sizeof(unsigned char));

  int round=((data_len+AES_BLOCK_SIZE-1)/AES_BLOCK_SIZE)*AES_BLOCK_SIZE;

  AES_KEY aes_k;
  AES_set_encrypt_key((const unsigned char*)p_key,128,&aes_k);

  for(int i=0;i<round; i++){
    if((i+1)*AES_BLOCK_SIZE > data_len){  // last partial block
      unsigned char b[AES_BLOCK_SIZE];
      memset(b,0,AES_BLOCK_SIZE);
      memcpy(b,data+(i*AES_BLOCK_SIZE),data_len-(i*AES_BLOCK_SIZE));
      AES_encrypt(data+(i*AES_BLOCK_SIZE),outbuf+(i*AES_BLOCK_SIZE),&aes_k);
    } else {  // full block
      AES_encrypt(data+(i*AES_BLOCK_SIZE),outbuf+(i*AES_BLOCK_SIZE),&aes_k);
    }
  }


  OCTETSTRING ret_val=OCTETSTRING(data_len,outbuf );
  return ret_val;
}

///////////////////////////////////////////////////////////////////////////////
//  Function: f_AES_ECB_128_Decrypt_OpenSSL
//
//  Purpose: Calculate AES 128 ECB decrypted value
//
//  Parameters:
//          p_key       - *in* *octetstring*   - Key
//          p_data      - *in* *octetstring*   - Data
//
//  Return Value:
//         octetstring - encrypted value
//
//  Errors:
//      -
//
//  Detailed description:
//      -
//
///////////////////////////////////////////////////////////////////////////////
OCTETSTRING f__AES__ECB__128__Decrypt__OpenSSL (const OCTETSTRING& p_key,const OCTETSTRING& p_data)
{
  if(p_key.lengthof()!=16){
    TTCN_error("f_AES_EBC_128_Decrypt_OpenSSL: The length of the key should be 16 instead of %d",p_key.lengthof() );
  }
  const unsigned char* data=(const unsigned char*)p_data;
  int data_len = p_data.lengthof();

  int outbuf_len=data_len+AES_BLOCK_SIZE;

  unsigned char* outbuf=(unsigned char*)Malloc(outbuf_len * sizeof(unsigned char));

  int round=((data_len+AES_BLOCK_SIZE-1)/AES_BLOCK_SIZE)*AES_BLOCK_SIZE;

  AES_KEY aes_k;
  AES_set_decrypt_key((const unsigned char*)p_key,128,&aes_k);

  for(int i=0;i<round; i++){
    if((i+1)*AES_BLOCK_SIZE > data_len){  // last partial block
      unsigned char b[AES_BLOCK_SIZE];
      memset(b,0,AES_BLOCK_SIZE);
      memcpy(b,data+(i*AES_BLOCK_SIZE),data_len-(i*AES_BLOCK_SIZE));
      AES_decrypt(data+(i*AES_BLOCK_SIZE),outbuf+(i*AES_BLOCK_SIZE),&aes_k);
    } else {  // full block
      AES_decrypt(data+(i*AES_BLOCK_SIZE),outbuf+(i*AES_BLOCK_SIZE),&aes_k);
    }
  }


  OCTETSTRING ret_val=OCTETSTRING(data_len,outbuf );
  return ret_val;
}
OCTETSTRING f__AES__CTR__128__Encrypt__Decrypt__OpenSSL (const OCTETSTRING& p_key,const OCTETSTRING& p_iv,const OCTETSTRING& p_data)
{
  if(p_key.lengthof()!=16){
    TTCN_error("f_AES_EBC_128_Decrypt_OpenSSL: The length of the key should be 16 instead of %d",p_key.lengthof() );
  }
  if(p_iv.lengthof()!=16){
    TTCN_error("f_AES_EBC_128_Decrypt_OpenSSL: The length of the IV should be 16 instead of %d",p_iv.lengthof() );
  }
  AES_KEY aes_k;
  AES_set_encrypt_key((const unsigned char*)p_key,128,&aes_k);

  int data_len=p_data.lengthof();
  unsigned char enc_data[data_len];
  unsigned char k_iv[AES_BLOCK_SIZE];
  memcpy(k_iv,(const unsigned char*)p_iv,AES_BLOCK_SIZE);

  unsigned int num = 0;
  unsigned char ecount_buf[AES_BLOCK_SIZE];
  memset(ecount_buf, 0, AES_BLOCK_SIZE);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  CRYPTO_ctr128_encrypt((const unsigned char*)p_data, enc_data, data_len, &aes_k, k_iv, ecount_buf, &num, (block128_f)AES_encrypt);
#else
  AES_ctr128_encrypt((const unsigned char*)p_data, enc_data, data_len, &aes_k, k_iv, ecount_buf, &num);
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */

  return OCTETSTRING(data_len, enc_data);
}

}
