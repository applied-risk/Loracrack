#include <stdio.h>
#include <stdlib.h>
#include <string.h>


// Exit and print error to stderr
void error_die(char *msg)
{
	fprintf(stderr, "%s\n", msg);
	exit(1);
}

// Hex to binary
// https://gist.github.com/xsleonard/7341172
unsigned char* hexstr_to_char(const char* hexstr)
{
	size_t len = strlen(hexstr);
	size_t final_len = len / 2;
	unsigned char* chrs = (unsigned char*)malloc((final_len+1) * sizeof(*chrs));
	for (size_t i=0, j=0; j<final_len; i+=2, j++)
		chrs[j] = (hexstr[i] % 32 + 9) % 25 * 16 + (hexstr[i+1] % 32 + 9) % 25;
	chrs[final_len] = '\0';
	return chrs;
}

// Validate hex input
void validate_hex_input(char *input) 
{
	size_t len = strlen(input);

	if (len > 256*2)
		error_die("Input too large");

	if (len % 2 != 0)
		error_die("Input not of even length");

	for (size_t i = 0; i < len; i++) {
		if ((input[i] >= 'a' && input[i] <= 'f') || (input[i] >= 'A' && input[i] <= 'F') || (input[i] >= '0' && input[i] <= '9')) 
			continue;
		else
			error_die("Invalid characters in input");
	}
}

// Function for printing bytes as hexadecimal
void printBytes(unsigned char *buf, size_t len) 
{
	for(int i=0; i<len; i++)
		printf("%02x", buf[i]);
}

// Get bits from an index
// https://www.geeksforgeeks.org/extract-k-bits-given-position-number/
int bitExtracted(int number, int k, int p) 
{
	return (((1 << k) - 1) & (number >> (p - 1))); 
} 


