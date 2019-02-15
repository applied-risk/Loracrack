loracrack_includes = includes/*.c -Lincludes/openssl-1.0.2q/ -Iincludes/openssl-1.0.2q/include/
cryptoz_linkert = -lcrypto -O3

default: all

all:
	gcc loracrack.c							$(loracrack_includes)	-o	loracrack							$(cryptoz_linkert)	-lpthread
	gcc loracrack_knownpt.c			$(loracrack_includes)	-o	loracrack_knownpt			$(cryptoz_linkert)	-lpthread
	gcc loracrack_decrypt.c			$(loracrack_includes)	-o	loracrack_decrypt			$(cryptoz_linkert)
	gcc loracrack_alterpacket.c	$(loracrack_includes)	-o	loracrack_alterpacket	$(cryptoz_linkert)
	gcc loracrack_genkeys.c			$(loracrack_includes)	-o	loracrack_genkeys			$(cryptoz_linkert)
	gcc loracrack_guessjoin.c		$(loracrack_includes)	-o	loracrack_guessjoin		$(cryptoz_linkert)

test:
	python unit_test.py
