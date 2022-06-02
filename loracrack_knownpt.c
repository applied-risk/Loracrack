/* 
	Sipke Mellema
	AR '19
*/

/* -------------------------------------------------------------------------- */
/* --- DEPENDENCIES --------------------------------------------------------- */

#include <unistd.h>
#include <string.h>

#include <stdbool.h>
#include <pthread.h>
#include <openssl/cmac.h>

#include "headers/loracrack.h"

/* -------------------------------------------------------------------------- */
/* --- CONSTANTS & TYPES ---------------------------------------------------- */

#define MType_UP 0 // uplink
#define MType_DOWN 1 // downlink

/* -------------------------------------------------------------------------- */
/* --- GLOBAL VARIABLES ----------------------------------------------------- */

// Variables shared among threads
volatile bool cracked = false;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

char *AppKey_hex = NULL;
char* packet_hex= NULL;
char* plain_text_hex = NULL;

unsigned char *AppKey;
unsigned char *packet;
unsigned char *plain_text;
unsigned char first_block_encrypted[16];
unsigned char A_1[16];

size_t plain_text_len = 0;

int verbose = 0;

/* -------------------------------------------------------------------------- */
/* --- MAIN FUNCTION -------------------------------------------------------- */

int main (int argc, char **argv)
{
	// Set number of threads
	// Intel(R) Core(TM) i5-7360U
	// See https://ark.intel.com/products/97535/Intel-Core-i5-7360U-Processor-4M-Cache-up-to-3-60-GHz-
	unsigned int n_threads = 4;

	// Set max App Nonce (<=16777216)
	unsigned int max_AppNonce = 16777216/10000; 

	// Process args
	int c;
	while ((c = getopt (argc, argv, "v:p:k:t:d:m:")) != -1) 
	{
		switch (c)
		{
			case 'k':
				AppKey_hex = optarg;
				break;
			case 'p':
				packet_hex = optarg;
				break;
			case 'd':
				plain_text_hex = optarg;
				break;
			case 'v':
				verbose = atoi(optarg);
				break;
			case 't':
				n_threads = atoi(optarg);
				break;
			case 'm':
				max_AppNonce = atoi(optarg);
				break;
		}
	}
	if (AppKey_hex == NULL || packet_hex == NULL)
		error_die("Usage: \
			\n\t./loracrack_knownpt -k <AppKey in hex> -p <raw_packet in hex> -d <plain_text in hex>\
			\nExample: \
			\n\t./loracrack_knownpt -k 88888888888888888888888888888888 -p 400267bd018005000142d9f48c52ea717c57 -d 33302e3332 -v 1\n");

	// Validate input - General
	validate_hex_input(AppKey_hex);
	validate_hex_input(packet_hex);
	validate_hex_input(plain_text_hex);

	// Store data length
	size_t AppKey_len = strlen(AppKey_hex) / 2;
	size_t packet_len = strlen(packet_hex) / 2;
	plain_text_len = strlen(plain_text_hex) / 2;

	// Validate input - Specific
	if (AppKey_len != 16)
		error_die("AppKey must be 16 bytes");
	if (packet_len <= 13)
		error_die("Packet data too small");

	// Convert to binary
	AppKey = hexstr_to_char(AppKey_hex);
	packet = hexstr_to_char(packet_hex);
	plain_text = hexstr_to_char(plain_text_hex);

	// Parse packet - MACHeader
	char MHDR = packet[0];
	int MType = bitExtracted(MHDR, 3, 6); // Byte 5-7

	if (MType < 2 || MType > 5)
		error_die("Packet not of type Data Up or Data Down");

	// Parse packet - Direction
	char Dir = 0;
	if (MType == 2 || MType == 4)
		Dir = MType_UP;
	if (MType == 3 || MType == 5)
		Dir = MType_DOWN;
	
	// Parse packet - Device address
	unsigned int DevAddr = 0;
	memcpy(&DevAddr, packet+1, 4);

	// Parse packet - FOptsLen
	int FCtrl = packet[5];
	int FOptsLen = bitExtracted(FCtrl, 4, 4);

	// Parse packet - FCnt
	short FCnt = 0;
	memcpy(&FCnt, packet+6, 2);

	// Skip FPort

	// Parse packet - FRMPayload
	size_t FRMPayload_index = 9 + FOptsLen;
	if (packet_len - 4 <= FRMPayload_index)
		error_die("No FRMPayload data");

	size_t FRMPayload_len = (packet_len - 4) - FRMPayload_index;
	unsigned char *FRMPayload = malloc(FRMPayload_len);
	memcpy(FRMPayload, packet+FRMPayload_index, FRMPayload_len);

	// Copy first encrypted block
	memcpy(first_block_encrypted, FRMPayload, 16);

	// Create A_1
	A_1[0] = 0x01;
	A_1[1] = 0x00;
	A_1[2] = 0x00;
	A_1[3] = 0x00;
	A_1[4] = 0x00;
	A_1[5] = Dir;
	A_1[6] = (DevAddr >> (8*0)) & 0xff;
	A_1[7] = (DevAddr >> (8*1)) & 0xff;
	A_1[8] = (DevAddr >> (8*2)) & 0xff;
	A_1[9] = (DevAddr >> (8*3)) & 0xff;
	A_1[10] = (FCnt >> (8*0)) & 0xff;
	A_1[11] = (FCnt >> (8*1)) & 0xff;
	A_1[12] = 0x00;
	A_1[13] = 0x00;
	A_1[14] = 0x00;
	A_1[15] = 0x01; // first block

	// Start cracking
	if (verbose) 
	{
		printf("------. L o R a C r a c k - Known Plaintext Attack ------\n");
		printf("\n\tBy Sipke Mellema '19\n\n");

		printf("Cracking with AppKey: ");
		printBytes(AppKey, 16);

		printf("\nFinding plaintext: ");
		printBytes(plain_text, plain_text_len);
	}

	// devide all possible nonces among threads
	unsigned int per_thread = max_AppNonce / n_threads;

	pthread_t tids[n_threads];

	if (verbose)
		printf("\n\nUsing %i threads, %i nonces per thread\n", n_threads, per_thread);

	unsigned long search_space = max_AppNonce * 0xffff;
	if (verbose)
		printf("max AppNonce = %u\nSearch space: %lu\n\n",max_AppNonce, search_space);

	// Create threads
	for (int i = 0; i < n_threads; i++) 
	{
		struct thread_args *thread_args = (struct thread_args *)malloc(sizeof(struct thread_args));

		thread_args->thread_ID = i;

		// Crack block size
		thread_args->AppNonce_start = i*per_thread;
		thread_args->AppNonce_end = (i*per_thread)+per_thread;

		// NetID zero for now
		thread_args->NetID_start = 0;
		// thread_args->NetID_end = 0;

		// Create thread
		pthread_t tid;
		pthread_create(&tid, NULL, loracrack_thread, (void *)thread_args);
		tids[i] = tid;
	}

	// Wait for threads to finish
	for (int i = 0; i < n_threads; i++)
		pthread_join(tids[i], NULL);

	return 0;
}



// Thread for for trying to crack certain ranges
void *loracrack_thread(void *vargp) 
{ 
	// Cipher vars
	EVP_CIPHER_CTX* ctx_aes128;
	EVP_CIPHER_CTX* ctx_aes128_buf;
	EVP_CIPHER_CTX* ctx_aes128_decrypt;

	// Output vars
	unsigned char AppSKey[16];
	int outlen;

	unsigned int thread_ID = ((struct thread_args*)vargp)->thread_ID;

	// 3 byte integers
	unsigned int AppNonce_current = ((struct thread_args*)vargp)->AppNonce_start;
	unsigned int AppNonce_end = ((struct thread_args*)vargp)->AppNonce_end;

	unsigned int NetID_start = ((struct thread_args*)vargp)->NetID_start;
	// unsigned int NetID_end = ((struct thread_args*)vargp)->NetID_end;

	// 2 byte integer
	unsigned short DevNonce = 0;

	if (verbose)
		printf("Thread %i cracking from AppNonce %i to %i\n", thread_ID, AppNonce_current, AppNonce_end);

	// Init ciphers
	ctx_aes128 = EVP_CIPHER_CTX_new();
	ctx_aes128_buf = EVP_CIPHER_CTX_new();
	ctx_aes128_decrypt = EVP_CIPHER_CTX_new();
	
	// Session key generation buffer
	unsigned char message[16], decrypt_result[16];
	memset(message, 0, 16);

	// Prepare message
	message[0] = 0x02;
	message[1] = (AppNonce_current >> (8*0)) & 0xff;
	message[2] = (AppNonce_current >> (8*1)) & 0xff;
	message[3] = (AppNonce_current >> (8*2)) & 0xff;
	message[4] = (NetID_start >> (8*0)) & 0xff;
	message[5] = (NetID_start >> (8*1)) & 0xff;
	message[6] = (NetID_start >> (8*2)) & 0xff;
	message[7] = (DevNonce >> (8*1)) & 0xff; // Reversed?
	message[8] = (DevNonce >> (8*0)) & 0xff;


	// Init aes context
	EVP_EncryptInit_ex(ctx_aes128_buf, EVP_aes_128_ecb(), NULL, AppKey, NULL);

	// AppNonce_end is exclusive
	while (AppNonce_current < AppNonce_end && !cracked) 
	{
		DevNonce = 0;

		if (verbose == 2)
			printf("Thread %i @ AppNonce %i\n", thread_ID, AppNonce_current);

		// Update AppNonce in message
		message[1] = (AppNonce_current >> (8*0)) & 0xff;
		message[2] = (AppNonce_current >> (8*1)) & 0xff;
		message[3] = (AppNonce_current >> (8*2)) & 0xff;

		while (DevNonce < 0xffff) 
		{
			// Update DevNonce in message
			message[7] = (DevNonce >> (8*1)) & 0xff; // Reversed?
			message[8] = (DevNonce >> (8*0)) & 0xff;

			EVP_EncryptInit_ex(ctx_aes128, EVP_aes_128_ecb(), NULL, AppKey, NULL);
			EVP_EncryptUpdate(ctx_aes128, AppSKey, &outlen, message, 16);

			EVP_EncryptInit_ex(ctx_aes128_decrypt, EVP_aes_128_ecb(), NULL, AppSKey, NULL);
			EVP_EncryptUpdate(ctx_aes128_decrypt, decrypt_result, &outlen, A_1, 16);

			for (int o = 0;o < plain_text_len; o++)
				decrypt_result[o] ^= first_block_encrypted[o];			

			if (memcmp(decrypt_result, plain_text, plain_text_len) == 0)
			{
				// cracked is used by multiple threads
				pthread_mutex_lock(&mutex);
				cracked = true;
				pthread_mutex_unlock(&mutex);

				// Output cracked results
				if (verbose)
					printf("\nOh dear lawd it's the same\n\n");

				if (verbose)
					printf("AppSKey,");

				printBytes(AppSKey, 16);
				printf(" ");

				message[0] = 0x01;
				EVP_EncryptInit_ex(ctx_aes128, EVP_aes_128_ecb(), NULL, AppKey, NULL);
				EVP_EncryptUpdate(ctx_aes128, AppSKey, &outlen, message, 16);

				if (verbose)
					printf("\nNwkSKey,");
				printBytes(AppSKey, 16);

				if (verbose) 
				{
					printf("\nAppNonce,%x\n", AppNonce_current);
					printf("DevNonce,%x\n", DevNonce);
				}
				printf("\n");

				// Clean aes data
				EVP_CIPHER_CTX_cleanup(ctx_aes128);

				break;
			}
			DevNonce += 1;

		}
		AppNonce_current += 1;
	}

  return NULL;

}

/* --- EOF ------------------------------------------------------------------ */