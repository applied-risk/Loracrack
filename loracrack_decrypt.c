/* 
	Sipke Mellema
	AR '19
*/

/* -------------------------------------------------------------------------- */
/* --- DEPENDENCIES --------------------------------------------------------- */

#include <unistd.h>
#include <string.h>
#include <math.h>
#include <stdbool.h>

#include <openssl/cmac.h>

#include "headers/loracrack.h"

/* -------------------------------------------------------------------------- */
/* --- CONSTANTS & TYPES ---------------------------------------------------- */

#define MType_UP 0 // uplink
#define MType_DOWN 1 // downlink

/* -------------------------------------------------------------------------- */
/* --- GLOBAL VARIABLES ----------------------------------------------------- */

char *AppSKey_hex = NULL;
char* packet_hex= NULL;
unsigned char *AppSKey;
unsigned char *packet;

/* -------------------------------------------------------------------------- */
/* --- MAIN FUNCTION -------------------------------------------------------- */

int main (int argc, char **argv)
{
	// Process args
	int c;
	while ((c = getopt (argc, argv, "vp:k:")) != -1)
	{
		switch (c)
		{
			case 'k':
				AppSKey_hex = optarg;
				break;
			case 'p':
				packet_hex = optarg;
				break;
		}
	}
	if (AppSKey_hex == NULL || packet_hex == NULL)
		error_die("Usage: \
			\n\t./loracrack_decrypt -k <decrypt key in hex> -p <raw_packet in hex> \
			\nExample: \
			\n\t./loracrack_decrypt -k 4899be88e40088c40abc703fa3ba1195 -p 400267bd018005000142d9f48c52ea717c57\n");

	// Validate input - General
	validate_hex_input(AppSKey_hex);
	validate_hex_input(packet_hex);

	// Store data length
	size_t AppSKey_len = strlen(AppSKey_hex) / 2;
	size_t packet_len = strlen(packet_hex) / 2;

	// Validate input - Specific
	if (AppSKey_len != 16)
		error_die("AppKey must be 16 bytes");
	if (packet_len <= 13)
		error_die("Packet data too small");

	// Convert to binary
	AppSKey = hexstr_to_char(AppSKey_hex);
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

	// Perform decryption
	char *decrypted = malloc(FRMPayload_len+1);
	double calc = FRMPayload_len;
	size_t nblocks = ceil(calc/16);

	// Cipher vars
	EVP_CIPHER_CTX *ctx_aes128;
	ctx_aes128 = EVP_CIPHER_CTX_new();

	// Encrypted block
	unsigned char block[16];

	int outlen;
	FRMPayload_index = 0;

	for (int i = 1; i < nblocks+1; i++) 
	{
		unsigned char A_i[] = { 0x01, 0x00, 0x00, 0x00, 0x00,
				Dir,
				(DevAddr >> (8*0)) & 0xff,
				(DevAddr >> (8*1)) & 0xff,
				(DevAddr >> (8*2)) & 0xff,
				(DevAddr >> (8*3)) & 0xff,
				(FCnt >> (8*0)) & 0xff,
				(FCnt >> (8*1)) & 0xff,
				0x00,
				0x00,
				0x00,
				i };

		EVP_EncryptInit_ex(ctx_aes128, EVP_aes_128_ecb(), NULL, AppSKey, NULL);
		EVP_EncryptUpdate(ctx_aes128, block, &outlen, A_i, 16);

		// XOR block with ciphertext
		for (int o = 0; o < 16; o++) 
		{
			decrypted[FRMPayload_index] = FRMPayload[FRMPayload_index] ^ block[o];
			FRMPayload_index += 1;
			if (FRMPayload_index > FRMPayload_len)
				break;
		}
		if (FRMPayload_index > FRMPayload_len)
				break;
	}

	decrypted[FRMPayload_index-1] = '\0';

	for (int i = 0 ; i < FRMPayload_len ; ++i) {
		printf("%02x", (unsigned char) decrypted[i]);
	}
	printf("\n");

	return 0;
}

/* --- EOF ------------------------------------------------------------------ */