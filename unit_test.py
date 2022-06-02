import subprocess
import sys

'''
	This command takes too long to compute the values, so we skip the tests for this one...

	7: ("./loracrack -k 88888888888888888888888888888888 -p 400267bd018005000142d9f48c52ea717c57", 
		"4899be88e40088c40abc703fa3ba1195 04068f88b9feee5385c67e033d911b4a")	
'''

cmd_output_dict = {
	
	1: ("./loracrack_decrypt -k 4899be88e40088c40abc703fa3ba1195 -p 400267bd018005000142d9f48c52ea717c57", 
		"33302e3332"),
	2: ("./loracrack_alterpacket -p 400267bd018005000142d9f48c52ea717c57 -a 4899be88e40088c40abc703fa3ba1195 -n 04068f88b9feee5385c67e033d911b4a -c 5 -d 33302e3332", 
		"400267bd018005000142d9f48c52ea717c57"),
	3: ("./loracrack_genkeys -k 88888888888888888888888888888888 -j 0000000000000000002bd61f000ba304000e1ba147157a -a 20adf6e18980952590fc1f7987a6913f35", 
		"4e1dcaf4f02fcd2ecbb1cb0d138fc53d 96eb9e13f0a3468ca580707ee688ee19"),
	4: ("./loracrack_guessjoin -p 0000000000000000002bd61f000ba304002f3b5785cf80 -f simplekeys", 
		"88888888888888888888888888888888"),
	5: ("./loracrack_testNwkSKeys -p 40F17DBE4900020001954378762B11FF0D -f simplekeys -v 0", 
		"MIC matches with possible NwkSKey --> 44024241ed4ce9a68c6a8bc055233fd3"),
	6: ("./loracrack_knownpt -k 88888888888888888888888888888888 -p 400267bd018005000142d9f48c52ea717c57 -d 33302e3332", 
		"4899be88e40088c40abc703fa3ba1195 04068f88b9feee5385c67e033d911b4a")
}

to_test = -1
if len(sys.argv) > 1:
	to_test = int(sys.argv[1])

for com in cmd_output_dict:
	if to_test != -1 and com != to_test:
		continue

	cmd, result = cmd_output_dict[com]

	print("[%s] Executing:\n\t%s" % (com, cmd))

	res = subprocess.check_output(cmd, shell=True).strip().decode("utf-8")
	print(res)

	if res == result:
		print("\t[V] Command works")

	else:
		print("\t[X] Command failed\n\tExpected: %s Got: %s\n\t" % (result, res))