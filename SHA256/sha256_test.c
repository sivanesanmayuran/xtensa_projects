/*********************************************************************
* Filename:   sha256.c
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Performs known-answer tests on the corresponding SHA1
	          implementation. These tests do not encompass the full
	          range of available test vectors, however, if the tests
	          pass it is very, very likely that the code is correct
	          and was compiled properly. This code also serves as
	          example usage of the functions.
*********************************************************************/

/*************************** HEADER FILES ***************************/
#include <stdio.h>
#include <memory.h>
#include <string.h>
#include "sha256.h"

/*********************** FUNCTION DEFINITIONS ***********************/
#define BITCOIN
#define SHA256_DIGEST_LENGTH SHA256_BLOCK_SIZE
#ifdef BITCOIN
typedef struct block_header {
	unsigned int	version;
	// dont let the "char" fool you, this is binary data not the human readable version
	unsigned char	prev_block[32];
	unsigned char	merkle_root[32];
	unsigned int	timestamp;
	unsigned int	bits;
	unsigned int	nonce;
} block_header;


// we need a helper function to convert hex to binary, this function is unsafe and slow, but very readable (write something better)
void hex2bin(unsigned char* dest, unsigned char* src)
{
	unsigned char bin;
	int c, pos;
	char buf[3];

	pos=0;
	c=0;
	buf[2] = 0;
	while(c < strlen(src))
	{
		// read in 2 characaters at a time
		buf[0] = src[c++];
		buf[1] = src[c++];
		// convert them to a interger and recast to a char (uint8)
		dest[pos++] = (unsigned char)strtol(buf, NULL, 16);
	}

}

// this function is mostly useless in a real implementation, were only using it for demonstration purposes
void hexdump(unsigned char* data, int len)
{
	int c;

	c=0;
	while(c < len)
	{
		printf("%.2x", data[c++]);
	}
	printf("\n");
}

// this function swaps the byte ordering of binary data, this code is slow and bloated (write your own)
void byte_swap(unsigned char* data, int len) {
	int c;
	unsigned char tmp[len];

	c=0;
	while(c<len)
	{
		tmp[c] = data[len-(c+1)];
		c++;
	}

	c=0;
	while(c<len)
	{
		data[c] = tmp[c];
		c++;
	}
}

int main() {
	// start with a block header struct
	block_header header;

	// we need a place to store the checksums
	unsigned char __attribute__((aligned(16))) hash1[SHA256_DIGEST_LENGTH];
	unsigned char __attribute__((aligned(16))) hash2[SHA256_DIGEST_LENGTH];

	// you should be able to reuse these, but openssl sha256 is slow, so your probbally not going to implement this anyway
	SHA256_CTX __attribute__((aligned(16))) sha256_pass1, sha256_pass2;


	// we are going to supply the block header with the values from the generation block 0
	header.version =	1;
	hex2bin(header.prev_block,		"0000000000000000000000000000000000000000000000000000000000000000");
	hex2bin(header.merkle_root,		"4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");
	header.timestamp =	1231006505;
	header.bits = 		486604799;
	header.nonce =		2083236893;

	// the endianess of the checksums needs to be little, this swaps them form the big endian format you normally see in block explorer
	byte_swap(header.prev_block, 32);
	byte_swap(header.merkle_root, 32);

	// dump out some debug data to the terminal
	//printf("sizeof(block_header) = %d\n", (int) sizeof(block_header));
	//printf("Block header (in human readable hexadecimal representation): ");
	//hexdump((unsigned char*)&header, sizeof(block_header));

	// Use SSL's sha256 functions, it needs to be initialized
	sha256_init(&sha256_pass1);
    // then you 'can' feed data to it in chuncks, but here were just making one pass cause the data is so small
	sha256_update(&sha256_pass1, (unsigned char*)&header, sizeof(block_header));
    // this ends the sha256 session and writes the checksum to hash1
	sha256_final(&sha256_pass1, hash1);

	// to display this, we want to swap the byte order to big endian
	byte_swap(hash1, SHA256_DIGEST_LENGTH);
	//printf("Useless First Pass Checksum: ");
	//hexdump(hash1, SHA256_DIGEST_LENGTH);

	// but to calculate the checksum again, we need it in little endian, so swap it back
	byte_swap(hash1, SHA256_DIGEST_LENGTH);

    //same as above
	sha256_init(&sha256_pass2);
	sha256_update(&sha256_pass2, hash1, SHA256_DIGEST_LENGTH);
	sha256_final(&sha256_pass2, hash2);

	byte_swap(hash2, SHA256_DIGEST_LENGTH);
	//printf("Target Second Pass Checksum: ");
	//hexdump(hash2, SHA256_DIGEST_LENGTH);

	return 0;
}

#else
int sha256_test()
{
	BYTE text1[] = {"abc"};
	BYTE text2[] = {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"};
	BYTE text3[] = {"aaaaaaaaaa"};
	BYTE hash1[SHA256_BLOCK_SIZE] = {0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
	                                 0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
	BYTE hash2[SHA256_BLOCK_SIZE] = {0x24,0x8d,0x6a,0x61,0xd2,0x06,0x38,0xb8,0xe5,0xc0,0x26,0x93,0x0c,0x3e,0x60,0x39,
	                                 0xa3,0x3c,0xe4,0x59,0x64,0xff,0x21,0x67,0xf6,0xec,0xed,0xd4,0x19,0xdb,0x06,0xc1};
	BYTE hash3[SHA256_BLOCK_SIZE] = {0xcd,0xc7,0x6e,0x5c,0x99,0x14,0xfb,0x92,0x81,0xa1,0xc7,0xe2,0x84,0xd7,0x3e,0x67,
	                                 0xf1,0x80,0x9a,0x48,0xa4,0x97,0x20,0x0e,0x04,0x6d,0x39,0xcc,0xc7,0x11,0x2c,0xd0};
	BYTE buf[SHA256_BLOCK_SIZE];
	SHA256_CTX __attribute__((aligned(16))) ctx;
	int idx;
	int pass = 1;

	sha256_init(&ctx);
	sha256_update(&ctx, text1, strlen(text1));
	sha256_final(&ctx, buf);
	pass = pass && !memcmp(hash1, buf, SHA256_BLOCK_SIZE);

	sha256_init(&ctx);
	sha256_update(&ctx, text2, strlen(text2));
	sha256_final(&ctx, buf);
	pass = pass && !memcmp(hash2, buf, SHA256_BLOCK_SIZE);

	sha256_init(&ctx);
	for (idx = 0; idx < 100000; ++idx)
	   sha256_update(&ctx, text3, strlen(text3));
	sha256_final(&ctx, buf);
	pass = pass && !memcmp(hash3, buf, SHA256_BLOCK_SIZE);

	return(pass);
}

int main()
{
	printf("SHA-256 tests: %s\n", sha256_test() ? "SUCCEEDED" : "FAILED");

	return(0);
}
#endif


