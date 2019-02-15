import sys


def get_simple_seqs(chars):
	for char_a in chars:
		yield char_a * 16
		for char_b in chars:
			if char_a != char_b:
				yield char_a + (char_b * 15)
				yield (char_b * 15) + char_b
				
def do_output(value):
	print value.encode('hex')


chars = ''.join([chr(i) for i in range(256)])

for i in range(256):
	tmp = chars[0]
	chars = chars[1:]
	chars = chars + tmp
	
	do_output(chars[:16])

chars = chars[::-1]
for i in range(256):
	tmp = chars[0]
	chars = chars[1:]
	chars = chars + tmp
	
	do_output(chars[:16])

chars = ''.join([chr(i) for i in range(256)])
for x in get_simple_seqs(chars):
	do_output(x)