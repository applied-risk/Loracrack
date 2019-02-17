/* 
	Sipke Mellema
	AR '19
*/


#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>

#include <openssl/cmac.h>

#include "headers/loracrack.h"


#define MType_UP 0 // uplink
#define MType_DOWN 1 // downlink



int verbose = 0;

// Variables shared among threads
volatile bool cracked = false;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

// Global variables
unsigned char *AppKey;
unsigned char *packet;
unsigned char MIC[4];
unsigned char *MIC_data;

size_t MIC_data_len = 0;


int main (int argc, char **argv)
{
	char *AppKey_hex = NULL, *packet_hex= NULL;

	// Set number of threads
	// Intel(R) Core(TM) i5-7360U
	// See https://ark.intel.com/products/97535/Intel-Core-i5-7360U-Processor-4M-Cache-up-to-3-60-GHz-
	unsigned int n_threads = 4;

	// Set max App Nonce (<=16777216)
	unsigned int max_AppNonce = 16777216/10000; 

	// Process args
	int c;
	while ((c = getopt (argc, argv, "v:p:k:t:m:")) != -1) 
	{
		switch (c)
		{
			case 'k':
				AppKey_hex = optarg;
				break;
			case 'p':
				packet_hex = optarg;
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
			\n\t./loracrack -k <AppKey in hex> -p <raw_packet in hex> \
			\nExample: \
			\n\t./loracrack -k 88888888888888888888888888888888 -p 400267bd018005000142d9f48c52ea717c57 \n");

	// Validate input - General
	validate_hex_input(AppKey_hex);
	validate_hex_input(packet_hex);

	// Store data length
	size_t AppKey_len = strlen(AppKey_hex) / 2;
	size_t packet_len = strlen(packet_hex) / 2;

	// Validate input - Specific
	if (AppKey_len != 16)
		error_die("AppKey must be 16 bytes");
	if (packet_len <= 13)
		error_die("Packet data too small");

	// Convert to binary
	AppKey = hexstr_to_char(AppKey_hex);
	packet = hexstr_to_char(packet_hex);

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

	// Parse MIC data

	int msg_len = packet_len - 4;

	// Create B0
	char B0[16];
	B0[0] = 0x49;
	B0[1] = 0x00;
	B0[2] = 0x00;
	B0[3] = 0x00;
	B0[4] = 0x00;
	B0[5] = Dir;
	B0[6] = (DevAddr >> (8*0)) & 0xff;
	B0[7] = (DevAddr >> (8*1)) & 0xff;
	B0[8] = (DevAddr >> (8*2)) & 0xff;
	B0[9] = (DevAddr >> (8*3)) & 0xff;
	B0[10] = (FCnt >> (8*0)) & 0xff;
	B0[11] = (FCnt >> (8*1)) & 0xff;
	B0[12] = 0x00;
	B0[13] = 0x00;
	B0[14] = 0x00;
	B0[15] = msg_len;

	// Copy MIC data
	MIC_data_len = 16 + msg_len;
	MIC_data = malloc(MIC_data_len+1);
	memcpy(MIC_data, B0, 16);
	memcpy(MIC_data+16, packet, msg_len);

	// Copy MIC
	MIC[0] = *(packet + (packet_len - 4));
	MIC[1] = *(packet + (packet_len - 3));
	MIC[2] = *(packet + (packet_len - 2));
	MIC[3] = *(packet + (packet_len - 1));

	// Start cracking
	if (verbose) 
	{
		printf("------. L o R a C r a c k  ------\n");
		printf("\n\tBy Sipke Mellema '19\n\n");

		printf("Cracking with AppKey:\t");
		printBytes(AppKey, 16);

		printf("\nTrying to find MIC:\t");
		printBytes(MIC, 4);
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
	EVP_CIPHER_CTX ctx_aes128, ctx_aes128_buf;
	CMAC_CTX *ctx_aes128_cmac;

	// Output vars
	unsigned char NwkSKey[16];
	unsigned char cmac_result[16]; 
	size_t cmac_result_len;
	int outlen;

	unsigned int thread_ID = ((struct thread_args*)vargp)->thread_ID;

	// 3 byte integers
	unsigned int AppNonce_current = ((struct thread_args*)vargp)->AppNonce_start;
	unsigned int AppNonce_end = ((struct thread_args*)vargp)->AppNonce_end;

	// NetID not yet implemented
	unsigned int NetID_start = ((struct thread_args*)vargp)->NetID_start;
	// unsigned int NetID_end = ((struct thread_args*)vargp)->NetID_end;

	// 2 byte integer
	unsigned short DevNonce = 0;

	if (verbose)
		printf("Thread %i cracking from AppNonce %i to %i\n", thread_ID, AppNonce_current, AppNonce_end);

	// Init ciphers
	EVP_CIPHER_CTX_init(&ctx_aes128);
	EVP_CIPHER_CTX_init(&ctx_aes128_buf);
	ctx_aes128_cmac = CMAC_CTX_new();

	// Session key generation buffer
	unsigned char message[16];
	memset(message, 0, 16);

	// NwkSKey = aes128_encrypt(AppKey, 0x01 | AppNonce | NetID | DevNonce | pad16)
	message[0] = 0x01;
	// https://stackoverflow.com/questions/7787423/c-get-nth-byte-of-integer
	message[1] = (AppNonce_current >> (8*0)) & 0xff;
	message[2] = (AppNonce_current >> (8*1)) & 0xff;
	message[3] = (AppNonce_current >> (8*2)) & 0xff;
	message[4] = (NetID_start >> (8*0)) & 0xff;
	message[5] = (NetID_start >> (8*1)) & 0xff;
	message[6] = (NetID_start >> (8*2)) & 0xff;
	message[7] = (DevNonce >> (8*1)) & 0xff; // Reversed?
	message[8] = (DevNonce >> (8*0)) & 0xff;

	EVP_EncryptInit_ex(&ctx_aes128_buf, EVP_aes_128_ecb(), NULL, AppKey, NULL);

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

			// NwkSKey = aes128_ecb(AppKey, message)
			// copy init state instead of calling EVP_EncryptInit_ex every time
			memcpy(&ctx_aes128, &ctx_aes128_buf, sizeof(ctx_aes128_buf));
			EVP_EncryptUpdate(&ctx_aes128, NwkSKey, &outlen, message, 16);
			
			// MIC = aes128_cmac(NwkSKey, MIC_data)
			CMAC_Init(ctx_aes128_cmac, NwkSKey, 16, EVP_aes_128_cbc(), NULL);
			CMAC_Update(ctx_aes128_cmac, MIC_data, MIC_data_len);
			CMAC_Final(ctx_aes128_cmac, cmac_result, &cmac_result_len);

			// Check if MIC matches MIC from packet
			if (memcmp(cmac_result, MIC, 4) == 0) 
			{

				// cracked is used by multiple threads
				pthread_mutex_lock(&mutex);
				cracked = true;
				pthread_mutex_unlock(&mutex);

				// Output cracked results
				if (verbose)
					printf("\nOh dear lawd it's the same\n\n");

				unsigned char AppSKey[16];
				
				message[0] = 0x02;
				EVP_EncryptInit_ex(&ctx_aes128, EVP_aes_128_ecb(), NULL, AppKey, NULL);
				EVP_EncryptUpdate(&ctx_aes128, AppSKey, &outlen, message, 16);

				if (verbose)
					printf("\nAppSKey,");
				printBytes(AppSKey, 16);
				
				printf(" ");

				if (verbose)
					printf("\nNwkSKey,");
				printBytes(NwkSKey, 16);
				
				if (verbose)
				{
					printf("\nAppNonce,%x\n", AppNonce_current);
					printf("DevNonce,%x\n", DevNonce);
				}

				// Clean aes data
				EVP_CIPHER_CTX_cleanup(&ctx_aes128);
				CMAC_CTX_free(ctx_aes128_cmac);

				break;
			}

			DevNonce += 1;

		}
		AppNonce_current += 1;
	}

    return NULL; 
} 
