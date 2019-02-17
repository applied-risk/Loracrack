# Uncomment to link to custom openssl 1.0.2 location
#openssl_include = includes/*.c -Lincludes/openssl-1.0.2q/ -Iincludes/openssl-1.0.2q/include/
otherlz_linkert = -lcrypto -O3 -Wall

default: all

all:
	gcc loracrack.c					$(openssl_include)	-o	loracrack				$(otherlz_linkert)	-lpthread
	gcc loracrack_knownpt.c			$(openssl_include)	-o	loracrack_knownpt		$(otherlz_linkert)	-lpthread
	gcc loracrack_decrypt.c			$(openssl_include)	-o	loracrack_decrypt		$(otherlz_linkert)
	gcc loracrack_alterpacket.c		$(openssl_include)	-o	loracrack_alterpacket	$(otherlz_linkert)
	gcc loracrack_genkeys.c			$(openssl_include)	-o	loracrack_genkeys		$(otherlz_linkert)
	gcc loracrack_guessjoin.c		$(openssl_include)	-o	loracrack_guessjoin		$(otherlz_linkert)

test:
	python unit_test.py
