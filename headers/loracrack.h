
// Exit and print error to stderr
void error_die(char *msg);

// Hex to binary
// https://gist.github.com/xsleonard/7341172
unsigned char* hexstr_to_char(const char* hexstr);

// Validate hex input
void validate_hex_input(char *input);

// Function for printing bytes as hexadecimal
void printBytes(unsigned char *buf, size_t len);

// Get bits from an index
// https://www.geeksforgeeks.org/extract-k-bits-given-position-number/
int bitExtracted(int number, int k, int p);

// Structure for arguments to threads
struct thread_args {

	unsigned int thread_ID;

	unsigned int AppNonce_start;
	unsigned int AppNonce_end;

	unsigned int NetID_start;
	unsigned int NetID_end;
};

// Thread for for trying to crack certain ranges
void *loracrack_thread(void *vargp);
