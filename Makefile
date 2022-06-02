# Insert the path of an openssl 1.1.* version. This path corresponds to a Linux installation
openssl_include = -L/usr/local/ssl/lib -I/usr/local/ssl/include
# Helper functions
helpers_include = includes/*.c
# Other repeatedly used options
otherlz_linkert = -lcrypto -O3 -Wall -ldl

default: all

all:
	gcc loracrack.c $(helpers_include) $(openssl_include) -o loracrack $(otherlz_linkert)	-lpthread
	gcc loracrack_knownpt.c $(helpers_include) $(openssl_include)	-o loracrack_knownpt $(otherlz_linkert)	-lpthread
	gcc loracrack_decrypt.c $(helpers_include) $(openssl_include)	-o loracrack_decrypt $(otherlz_linkert)	-lm
	gcc loracrack_alterpacket.c $(helpers_include) $(openssl_include)	-o loracrack_alterpacket	$(otherlz_linkert)	-lm
	gcc loracrack_genkeys.c $(helpers_include) $(openssl_include)	-o loracrack_genkeys $(otherlz_linkert)
	gcc loracrack_guessjoin.c $(helpers_include) $(openssl_include)	-o loracrack_guessjoin $(otherlz_linkert)
	gcc loracrack_testNwkSKeys.c $(helpers_include) $(openssl_include)	-o loracrack_testNwkSKeys $(otherlz_linkert)

clear:
	rm loracrack
	rm loracrack_knownpt
	rm loracrack_decrypt
	rm loracrack_alterpacket
	rm loracrack_genkeys
	rm loracrack_guessjoin
	rm loracrack_testkeys

test:
	python unit_test.py
