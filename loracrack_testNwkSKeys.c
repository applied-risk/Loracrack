/* 
	Vincent Lopes & Julien Fink

	Example of packets with their NwkSKey :

		packet_hex = "40F17DBE4900020001954378762B11FF0D";
		NwkSKey_hex = "44024241ed4ce9a68c6a8bc055233fd3";

		packet_hex = "400267bd018005000142d9f48c52ea717c57";
		NwkSKey_hex = "04068f88b9feee5385c67e033d911b4a";
*/

/* -------------------------------------------------------------------------- */
/* --- DEPENDENCIES --------------------------------------------------------- */

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include <openssl/cmac.h>

#include "headers/loracrack.h"

/* -------------------------------------------------------------------------- */
/* --- CONSTANTS & TYPES ---------------------------------------------------- */

#define MType_UP 0 // uplink
#define MType_DOWN 1 // downlink

/* -------------------------------------------------------------------------- */
/* --- GLOBAL VARIABLES ----------------------------------------------------- */

unsigned char* packet;
char* packet_hex = NULL;

unsigned char* NwkSKey;
char* NwkSKey_hex;

// File containing NwkSKeys
char* filename = NULL;

// MIC extracted from the packet
unsigned char MIC[4];

// New MIC declaration for the AES_HMAC computation
unsigned char MIC_computed[16];
size_t length_MIC_computed;

// Data (i.e. B0 | msg) to be HMACed in order to verify if the NwkSKey used computes the right MIC
int data_to_be_HMACed_len;
char* data_to_be_HMACed;

bool MIC_matches_with_NwkSKey = false;

int verbose = 0;

/* -------------------------------------------------------------------------- */
/* --- MAIN FUNCTION -------------------------------------------------------- */

int main (int argc, char **argv)
{
	// Process args
	int c;
	while ((c = getopt (argc, argv, "v:p:f:")) != -1) 
	{
		switch (c)
		{
			case 'p':
				packet_hex = optarg;
				break;
			case 'f':
				filename = optarg;
				break;
			case 'v':
				verbose = atoi(optarg);
				break;
		}
	}
	if (packet_hex == NULL || filename == NULL)
		error_die("Usage: \
			\n\t./loracrack_testkeys -p <raw_packet in hex> -f <file with NwkSKeys in hex> -v <a number different from zero>\
			\nExample: \
			\n\t./loracrack_testkeys -p 40F17DBE4900020001954378762B11FF0D -f simplekeys -v 0\n");

	// Validate input - General
	validate_hex_input(packet_hex);

	// Store data length
	size_t packet_len = strlen(packet_hex) / 2;

	// Convert to binary
	packet = hexstr_to_char(packet_hex);

	// Parse packet - MACHeader
	char MHDR = packet[0];
	int MType = bitExtracted(MHDR, 3, 6);

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

	// Parse packet - FCnt
	short FCnt = 0;
	memcpy(&FCnt, packet+6, 2);

	int packet_len_without_MIC = packet_len - 4;

	// The creation of B0 is different between LoRaWAN 1.0.3 and LoRaWAN 1.1 - check the documentation
	char B0[32];
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
	B0[15] = packet_len_without_MIC;

	// Check lorawan1.0.3 documentation, page 21 for explanations
	data_to_be_HMACed_len = 16 + packet_len_without_MIC;
	data_to_be_HMACed = malloc(data_to_be_HMACed_len + 1);
	
	// Concatenation of B0 | msg
	memcpy(data_to_be_HMACed, B0, 16);
	memcpy(data_to_be_HMACed + 16, packet, packet_len_without_MIC);

	// Parse packet - MIC
	MIC[0] = *(packet+(packet_len - 4));
	MIC[1] = *(packet+(packet_len - 3));
	MIC[2] = *(packet+(packet_len - 2));
	MIC[3] = *(packet+(packet_len - 1));

	// CMAC declaration
	CMAC_CTX *ctx_aes128_cmac;
	ctx_aes128_cmac = CMAC_CTX_new();

	// Arguments for the file opening task
	FILE *fp;
	char *line = NULL;
	size_t len = 0;
	ssize_t read;

	// Read file with keys
	fp = fopen(filename, "r");

	if (fp == NULL)
		error_die("Could not open file");

	while((read = getline(&line, &len, fp)) != -1)
	{

		NwkSKey_hex = line;
		size_t NwkSKey_len = strlen(NwkSKey_hex) / 2;
		if (NwkSKey_len != 16)
			error_die("NwkSKey must be 16 bytes");

		NwkSKey = hexstr_to_char(line);

		if (verbose == 1) 
		{
			printf("Trying key --> ");
			printBytes(NwkSKey, 16);
			printf("\n");
		}

		// Surprisingly, the type of AES used is cbc and not ccm* as stated in the LoRaWAN 1.0.3 documentation
		CMAC_Init(ctx_aes128_cmac, NwkSKey, 16, EVP_aes_128_cbc(), NULL);
		CMAC_Update(ctx_aes128_cmac, data_to_be_HMACed, data_to_be_HMACed_len);
		CMAC_Final(ctx_aes128_cmac, MIC_computed, &length_MIC_computed);

		// Check if the MIC computed matches the MIC from the packet
		if (memcmp(MIC_computed, MIC, 4) == 0)
		{
			printf("\nMIC matches with possible NwkSKey --> ");
			printBytes(NwkSKey, 16);
			printf ("\n\n");
			MIC_matches_with_NwkSKey = true;
		}

	}

	fclose(fp);
	printf("\n");

	if(!MIC_matches_with_NwkSKey)
	{
		printf("No NwkSKey matching the MIC has been found.\n\n");
	}
	
	return 0;
}

/* --- EOF ------------------------------------------------------------------ */