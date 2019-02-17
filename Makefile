# Can be used to link to custom openssl 1.0.* location
openssl_include = -Lincludes/openssl-1.0.2q/ -Iincludes/openssl-1.0.2q/include/
# Helper functions
helpers_include = includes/*.c
# Other repeatedly used options
otherlz_linkert = -lcrypto -O3 -Wall

default: all

all:
	gcc loracrack.c $(helpers_include) $(openssl_include) -o loracrack $(otherlz_linkert)	-lpthread
	gcc loracrack_knownpt.c $(helpers_include) $(openssl_include)	-o loracrack_knownpt $(otherlz_linkert)	-lpthread
	gcc loracrack_decrypt.c $(helpers_include) $(openssl_include)	-o loracrack_decrypt $(otherlz_linkert)	-lm
	gcc loracrack_alterpacket.c $(helpers_include) $(openssl_include)	-o loracrack_alterpacket	$(otherlz_linkert)	-lm
	gcc loracrack_genkeys.c $(helpers_include) $(openssl_include)	-o loracrack_genkeys $(otherlz_linkert)
	gcc loracrack_guessjoin.c $(helpers_include) $(openssl_include)	-o loracrack_guessjoin $(otherlz_linkert)

clear:
	rm loracrack
	rm loracrack_knownpt
	rm loracrack_decrypt
	rm loracrack_alterpacket
	rm loracrack_genkeys
	rm loracrack_guessjoin

test:
	python unit_test.py
