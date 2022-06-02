/* 
	Sipke Mellema
	AR '19
*/

/* -------------------------------------------------------------------------- */
/* --- DEPENDENCIES --------------------------------------------------------- */

#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <openssl/cmac.h>

#include "headers/loracrack.h"

/* -------------------------------------------------------------------------- */
/* --- GLOBAL VARIABLES ----------------------------------------------------- */

char *AppKey_hex = NULL;
char* join_packet_hex= NULL;
char* accept_packet_hex= NULL;
unsigned char *AppKey;
unsigned char *join_packet;
unsigned char *accept_packet;

/* -------------------------------------------------------------------------- */
/* --- MAIN FUNCTION -------------------------------------------------------- */

int main (int argc, char **argv)
{
	// Process args
	int c;
	int verbose = 0;
	while ((c = getopt (argc, argv, "v:k:j:a:")) != -1) 
	{
		switch (c)
		{
			case 'k':
				AppKey_hex = optarg;
				break;
			case 'j':
				join_packet_hex = optarg;
				break;
			case 'a':
				accept_packet_hex = optarg;
				break;
			case 'v':
				verbose = atoi(optarg);
				break;
		}
	}
	if (AppKey_hex == NULL || join_packet_hex == NULL || accept_packet_hex == NULL)
		error_die("Usage: \
			\n\t./loracrack_genkeys -k <AppKey in hex> -j <join_packet in hex> -a <accept_packet in hex> \
			\nExample: \
			\n\t./loracrack_genkeys -k 88888888888888888888888888888888 -j 0000000000000000002bd61f000ba304000e1ba147157a -a 20adf6e18980952590fc1f7987a6913f35 -v 0\n");

	// Validate input - General
	validate_hex_input(AppKey_hex);
	validate_hex_input(join_packet_hex);
	validate_hex_input(accept_packet_hex);

	// Store data length
	size_t AppKey_len = strlen(AppKey_hex) / 2;
	size_t join_packet_len = strlen(join_packet_hex) / 2;
	size_t accept_packet_len = strlen(accept_packet_hex) / 2;

	// Validate input - Specific
	if (AppKey_len != 16)
		error_die("AppKey must be 16 bytes");
	if (join_packet_len != 23)
		error_die("Join packet incorrect size (not 23 bytes)");
	if (accept_packet_len < 16)
		error_die("Accept packet too small");

	// Convert to binary
	AppKey = hexstr_to_char(AppKey_hex);
	join_packet = hexstr_to_char(join_packet_hex);
	accept_packet = hexstr_to_char(accept_packet_hex);

	// Grab data from packets
	unsigned short DevNonce;
	unsigned int AppNonce, NetID;

	unsigned char block[16];
	unsigned char accept_packet_block[16];
	int outlen;

	// Cipher vars
	EVP_CIPHER_CTX *ctx_aes128;
	ctx_aes128 = EVP_CIPHER_CTX_new();

	// Decrypt accept packet
	memcpy(accept_packet_block, accept_packet+1, 16);

	EVP_EncryptInit_ex(ctx_aes128, EVP_aes_128_ecb(), NULL, AppKey, NULL);
	// Because Join-Response is encrypted with decrypt()
	EVP_EncryptUpdate(ctx_aes128, block, &outlen, accept_packet_block, 16);

	// Get variables
	memcpy(&DevNonce, join_packet+17, 2);
	memcpy(&AppNonce, block, 3);
	memcpy(&NetID, block+3, 3);

	if (verbose) 
	{
		printf("\nDevNonce: %x\n", DevNonce);
		// printBytes(DevNonce, 2);
		printf("AppNonce: %x\n", AppNonce);
		// printBytes(AppNonce, 3);
		printf("NetID: %x\n", NetID);
		// printBytes(NetID, 3);
		printf("\n");
	}

	// Session key generation buffer
	unsigned char message[16];
	memset(message, 0, 16);

	// NwkSKey = aes128_encrypt(AppKey, 0x01 | AppNonce | NetID | DevNonce | pad16)
	message[0] = 0x01;
	// https://stackoverflow.com/questions/7787423/c-get-nth-byte-of-integer
	message[1] = (AppNonce >> (8*0)) & 0xff;
	message[2] = (AppNonce >> (8*1)) & 0xff;
	message[3] = (AppNonce >> (8*2)) & 0xff;
	message[4] = (NetID >> (8*0)) & 0xff;
	message[5] = (NetID >> (8*1)) & 0xff;
	message[6] = (NetID >> (8*2)) & 0xff;
	message[7] = (DevNonce >> (8*0)) & 0xff; // Reversed?
	message[8] = (DevNonce >> (8*1)) & 0xff;

	// Generate keys

	// NwkSKey
	unsigned char NwkSKey[16];
	EVP_EncryptInit_ex(ctx_aes128, EVP_aes_128_ecb(), NULL, AppKey, NULL);
	EVP_EncryptUpdate(ctx_aes128, NwkSKey, &outlen, message, 16);

	if (verbose)
		printf("NwkSKey: ");
	printBytes(NwkSKey, 16);
	printf(" ");

	// AppSEncKey
	message[0] = 0x02;
	EVP_EncryptInit_ex(ctx_aes128, EVP_aes_128_ecb(), NULL, AppKey, NULL);
	EVP_EncryptUpdate(ctx_aes128, NwkSKey, &outlen, message, 16);

	if (verbose)
		printf("AppSKey: ");
	printBytes(NwkSKey, 16);
	printf("\n");

	return 0;
}

/* --- EOF ------------------------------------------------------------------ */