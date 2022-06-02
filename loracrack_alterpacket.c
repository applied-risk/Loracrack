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

char* NwkSKey_hex = NULL;
char* AppSKey_hex = NULL;
char* packet_hex = NULL;
char* data_hex = NULL;
unsigned char *NwkSKey;
unsigned char *AppSKey;
unsigned char *packet;
unsigned char *data;

/* -------------------------------------------------------------------------- */
/* --- MAIN FUNCTION -------------------------------------------------------- */

int main (int argc, char **argv)
{	
	// Process args
	int c;
	short new_FCnt = 0;
	while ((c = getopt (argc, argv, "p:n:a:c:d:")) != -1) 
	{
		switch (c)
		{
			case 'p':
				packet_hex = optarg;
				break;
			case 'n':
				NwkSKey_hex = optarg;
				break;
			case 'a':
				AppSKey_hex = optarg;
				break;
			case 'c':
				new_FCnt = atoi(optarg);
				break;
			case 'd':
				data_hex = optarg;
				break;
		}
	}
	if (AppSKey_hex == NULL || packet_hex == NULL || NwkSKey_hex == NULL || data_hex == NULL)
		error_die("Usage: \
			\n\t./loracrack_alterpacket -p <raw_packet in hex> -a <AppSKey in hex> -n <NwkSKey in hex> -c <Fctn> -d <new data in hex>\
			\nExample: \
			\n\t./loracrack_alterpacket -p 400267bd018005000142d9f48c52ea717c57 -a 4899be88e40088c40abc703fa3ba1195 -n 04068f88b9feee5385c67e033d911b4a -c 5 -d 33302d3332\n");

	// Validate input - General
	validate_hex_input(AppSKey_hex);
	validate_hex_input(NwkSKey_hex);
	validate_hex_input(data_hex);
	validate_hex_input(packet_hex);

	// Store data length
	size_t AppSKey_len = strlen(AppSKey_hex) / 2;
	size_t NwkSKey_len = strlen(NwkSKey_hex) / 2;
	size_t data_len = strlen(data_hex) / 2;
	size_t packet_len = strlen(packet_hex) / 2;

	// Validate input - Specific
	if (AppSKey_len != 16)
		error_die("AppSKey must be 16 bytes");
	if (NwkSKey_len != 16)
		error_die("NwkSKey must be 16 bytes");
	if (packet_len <= 13)
		error_die("Packet data too small");
	if (data_len > 255-13)
		error_die("Data too large");

	// Convert to binary
	AppSKey = hexstr_to_char(AppSKey_hex);
	NwkSKey = hexstr_to_char(NwkSKey_hex);
	data = hexstr_to_char(data_hex);
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
	// Change FCnt?
	if (new_FCnt != 0)
	{
		// Alter in packet
		memcpy(packet+6, &new_FCnt, 2);
		// Save new FCnt
		FCnt = new_FCnt;
	}
	else
	{
		// Default is increase counter by 1
		FCnt += 1;
		// Alter in packet
		memcpy(packet+6, &FCnt, 2);
	}

	// Skip FPort

	// Parse packet - FRMPayload
	size_t FRMPayload_index = 9 + FOptsLen;
	if (packet_len - 4 <= FRMPayload_index)
		error_die("No FRMPayload data");

	// Resize the packet for the new data
	size_t FRMPayload_len = (packet_len - 4) - FRMPayload_index;
	// Update packet len
	packet_len = (packet_len - FRMPayload_len) + data_len;
	packet = realloc(packet, packet_len);

	// Perform decryption
	double calc = data_len;
	size_t nblocks = ceil(calc/16);

	// Cipher vars
	EVP_CIPHER_CTX *ctx_aes128;
	ctx_aes128 = EVP_CIPHER_CTX_new();

	// For decrypted block
	unsigned char block[16];

	int outlen;
	int data_index = 0;

	// Encrypt and write new data
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

		// XOR block with plaintext
		for (int o = 0; o < 16; o++) 
		{
			packet[FRMPayload_index + data_index] = data[data_index] ^ block[o];

			data_index += 1;
			if (data_index > data_len)
				break;
		}
		if (data_index > data_len)
				break;
	}

	// MIC (CMAC) variables
	CMAC_CTX *ctx_aes128_cmac;
	ctx_aes128_cmac = CMAC_CTX_new();

	unsigned char cmac_result[16]; 
	size_t cmac_result_len;

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
	int MIC_data_len = 16 + msg_len;
	char *MIC_data = malloc(MIC_data_len+1);
	memcpy(MIC_data, B0, 16);
	memcpy(MIC_data+16, packet, msg_len);

	// Recalculate MIC
	CMAC_Init(ctx_aes128_cmac, NwkSKey, 16, EVP_aes_128_cbc(), NULL);
	CMAC_Update(ctx_aes128_cmac, MIC_data, MIC_data_len);
	CMAC_Final(ctx_aes128_cmac, cmac_result, &cmac_result_len);

	// Write new MIC
	packet[packet_len - 4] = cmac_result[0];
	packet[packet_len - 3] = cmac_result[1];
	packet[packet_len - 2] = cmac_result[2];
	packet[packet_len - 1] = cmac_result[3];	

	// Print new packet
	printBytes(packet, packet_len);
	printf("\n");

	return 0;
}

/* --- EOF ------------------------------------------------------------------ */