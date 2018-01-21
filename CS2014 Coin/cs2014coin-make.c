/*!
 * @file cs2014coin-make.c
 * @brief This is the implementation of the cs2014 coin maker
 *
 * It should go without saying that these coins are for play:-)
 * 
 * This is part of CS2014
 *    https://down.dsg.cs.tcd.ie/cs2014/examples/c-progs-2/README.html
 */

/* 
 * Copyright (c) 2017 stephen.farrell@cs.tcd.ie
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

#include "cs2014coin.h"
#include "cs2014coin-int.h"

#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include "mbedtls/md.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#include <time.h>
#include <stdlib.h>

#include "cs2014coin.h"
#include "cs2014coin-int.h"
#define CC_DEBUG
#define p256NIST		MBEDTLS_ECP_DP_SECP521R1  		//MBEDTLS_ECP_DP_SECP256R1

#define DFL_TYPE                MBEDTLS_PK_ECKEY
#define DFL_EC_CURVE            mbedtls_ecp_curve_list()->grp_id

#define KEYSIZE 158
#define NONCELEN 32
#define HASHLEN 32
#define BUFFERLEN 1000
#define LENTOHASH 242
#define COINFOUND CS2014COIN_MAXITER + 1

void incr_nonce(unsigned char *ptr, unsigned char* guard_ptr)
{
    if ((ptr-1)==guard_ptr) 
    	return;

    unsigned char ch=*(ptr-1);
    if (ch==255) 
    {
        incr_nonce(ptr-1,guard_ptr);
        *(ptr-1)=0;
    } 
    else 
        *(ptr-1)=(ch+1);

    return;
}

int cs2014coin_make(int bits, unsigned char *buf, int *buflen)
{
	// Initializing known values

	unsigned char powBuffer[BUFFERLEN];
	memset(powBuffer, 0, BUFFERLEN);
	unsigned char *powbuff = powBuffer;

	cs2014coin_t mycoin;
	mycoin.ciphersuite = CS2014COIN_CS_0;
	mycoin.bits = bits;
	mycoin.keylen = KEYSIZE;
	mycoin.noncelen = NONCELEN;
	mycoin.hashlen = HASHLEN;

	/*
	printf("Ciphersuite: %d \n", mycoin.ciphersuite);
	printf("Bits: %d \n", mycoin.bits);
	printf("Key Length: %d \n", mycoin.keylen);
	printf("Hash Length: %d \n", mycoin.hashlen);
	*/

	// Public key generation

	mbedtls_pk_context key;
	mbedtls_pk_init(&key);
	mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));

	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ctr_drbg_init(&ctr_drbg);

	mbedtls_entropy_context entropy;
	mbedtls_entropy_init(&entropy);

	const char *pers = "gen_key";

	mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen(pers));

	mbedtls_ecp_gen_key(/*mbedtls_ecp_curve_list()->grp_id*/ MBEDTLS_ECP_DP_SECP521R1, mbedtls_pk_ec(key), mbedtls_ctr_drbg_random, &ctr_drbg);

	unsigned char publicKey[KEYSIZE];
	unsigned char *pubKey = publicKey;

	memset(publicKey, 0, KEYSIZE);

	int r = mbedtls_pk_write_pubkey_der(&key, publicKey, KEYSIZE);
	size_t len = r;

 	pubKey = publicKey + sizeof(publicKey) - len;

    mycoin.keyval = pubKey; 

	//dumpbuf("publicKey: ", mycoin.keyval, KEYSIZE);

	// Initializing nonce as random

	unsigned char nonce[NONCELEN];
	unsigned char *noncePointer = nonce;
	int rv = mbedtls_ctr_drbg_random(&ctr_drbg, noncePointer, NONCELEN);
	if(rv != 0)
	{
		fprintf(stderr, "RNG function error");
		return(-1);
	}

	mycoin.nonceval = noncePointer;

	//Adding values into our coin buffer

	int temp = htonl(mycoin.ciphersuite);
	memcpy(powbuff, &temp, 4);

	powbuff += 4;
	temp = htonl(mycoin.bits);
	memcpy(powbuff, &temp, 4);

	powbuff += 4;
	temp = htonl(mycoin.keylen);
	memcpy(powbuff, &temp, 4);

	powbuff += 4;
	memcpy(powbuff, mycoin.keyval, KEYSIZE);

	powbuff += KEYSIZE;
	temp = htonl(mycoin.noncelen);
	memcpy(powbuff, &temp, 4);

	powbuff += 4;
	memcpy(powbuff, mycoin.nonceval, NONCELEN);

	powbuff += NONCELEN;
		temp = htonl(mycoin.hashlen);
		memcpy(powbuff, &temp, 4);

	//dumpbuf("Coin so far: ", powBuffer, BUFFERLEN);

	// Hashing our values

	mbedtls_md_context_t sha_ctx;

	mbedtls_md_init(&sha_ctx);
	mbedtls_md_setup(&sha_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);

	unsigned char powHash[HASHLEN];
	unsigned char *hash = powHash;
	unsigned char *guard = mycoin.nonceval;
	unsigned char *endOfNonce = mycoin.nonceval + NONCELEN;

	// Incrementing nonce to find a coin

	int iterations = 0;
	while(iterations < CS2014COIN_MAXITER)
	{	
		mbedtls_md_starts(&sha_ctx);       
        mbedtls_md_update(&sha_ctx, (unsigned char *) powBuffer, LENTOHASH);    
        mbedtls_md_finish(&sha_ctx, hash);

        if(zero_bits(mycoin.bits, hash, HASHLEN))
        {
        	//printf("We found one boys!\n");
        	//dumpbuf("Winning Hash: ", hash, HASHLEN);
        	iterations = COINFOUND;
        }
		else
		{
			incr_nonce(endOfNonce, guard);
			memcpy(powbuff, mycoin.nonceval, NONCELEN);
			iterations++;
		}
	}

	dumpbuf("Hashed: ", powbuff, 300);

	// Either found a coin or we reached the max  iteration count.

	if(iterations == COINFOUND)
	{
		//printf("You found a coin!\n");

		powbuff += 4;
		memcpy(powbuff, hash, HASHLEN);

		unsigned char signature[BUFFERLEN];
		size_t signatureLen = 0;

		mbedtls_pk_sign(&key, MBEDTLS_MD_SHA256, hash, HASHLEN, signature, &signatureLen, mbedtls_ctr_drbg_random, NULL);

		int signatureLength = (int) signatureLen;

		powbuff += HASHLEN;
		temp = htonl(signatureLength);
		memcpy(powbuff, &temp, 4);

		powbuff += 4;
		memcpy(powbuff, signature, signatureLen);

		int coinSize = 246 + signatureLen;

		//dumpbuf("Winning coin!", powBuffer, coinSize);

		unsigned char coin[coinSize];
		memset(coin, 0, coinSize);
		memcpy(coin, powBuffer, coinSize);

		memset(buf, 0 , CS2014COIN_BUFSIZE);
		memcpy(buf, coin, coinSize);

		*buflen = coinSize;
	}
	else
	{
		fprintf(stderr, "No coin found\n");
		return(-1);
	}

	return(0);
}


