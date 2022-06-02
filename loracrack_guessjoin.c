/* 
	Sipke Mellema
	AR '19
*/

/* -------------------------------------------------------------------------- */
/* --- DEPENDENCIES --------------------------------------------------------- */

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/cmac.h>

#include "headers/loracrack.h"

/* -------------------------------------------------------------------------- */
/* --- GLOBAL VARIABLES ----------------------------------------------------- */

char *packet_hex = NULL;
char* filename = NULL;

unsigned char *packet;
unsigned char *MIC_data;
unsigned char MIC[4];
size_t MIC_data_len = 0;

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
	if (packet_hex == NULL)
		error_die("Usage: \
			\n\t./loracrack_guessjoin -p <raw_packet in hex> -f <file with AppKeys in hex>\
			\nExample: \
			\n\t./loracrack_guessjoin -p 0000000000000000002bd61f000ba304002f3b5785cf80 -f simplekeys -v 0\n");

	// Validate input - General
	validate_hex_input(packet_hex);

	// Store data length
	size_t packet_len = strlen(packet_hex) / 2;

	// Validate input - Specific
	if (packet_len != 23)
		error_die("Packet not the right size");

	// Convert to binary
	packet = hexstr_to_char(packet_hex);

	// Parse packet - MIC
	MIC[0] = *(packet+(packet_len - 4));
	MIC[1] = *(packet+(packet_len - 3));
	MIC[2] = *(packet+(packet_len - 2));
	MIC[3] = *(packet+(packet_len - 1));
 
	// Get MIC data (rest of packet)
	MIC_data_len = packet_len - 4;
	MIC_data = malloc(MIC_data_len);

	memcpy(MIC_data, packet, MIC_data_len);

	if (verbose)
	{
		printf("------. L o R a C r a c k - Guess Appkey for joinpacket ------\n");
		printf("\n\tBy Sipke Mellema '19\n\n");

		printf("\nTrying to find MIC: ");
		printBytes(MIC, 4);
		printf("\n");
	}

	CMAC_CTX *ctx_aes128_cmac;
	ctx_aes128_cmac = CMAC_CTX_new();

	unsigned char cmac_result[16]; 
	size_t cmac_result_len;

	FILE *fp;
	char *line = NULL;
	size_t len = 0;
	ssize_t read;

	// Read file with keys
	fp = fopen(filename, "r");

	if (fp == NULL)
		error_die("Could not open file");

	// Try all keys
	unsigned char *AppKey;
	while((read = getline(&line, &len, fp)) != -1)
	{
		AppKey = hexstr_to_char(line);

		if (verbose == 2) 
		{
			printf("Trying key: ");
			printBytes(AppKey,16);
			printf("\n");
		}

		CMAC_Init(ctx_aes128_cmac, AppKey, 16, EVP_aes_128_cbc(), NULL);
		CMAC_Update(ctx_aes128_cmac, MIC_data, MIC_data_len);
		CMAC_Final(ctx_aes128_cmac, cmac_result, &cmac_result_len);

		// Check if MIC matches MIC from packet
		if (memcmp(cmac_result, MIC, 4) == 0) 
		{
			if (verbose)
				printf("MIC found with possible AppKey:");
			printBytes(AppKey, 16);
			printf ("\n");
		}
	}

	fclose(fp);
	return 0;
}

/* --- EOF ------------------------------------------------------------------ */