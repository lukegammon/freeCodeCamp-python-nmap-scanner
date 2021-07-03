import nmap

scanner = nmap.PortScanner()

print("Welcome, this is a simple nmap automation tool")
print("----------------------------------------------")

ip_address = input("Please enter the ip address you would like to scan: ")
print("The IP you entered is: ", ip_address)
type(ip_address)

response = input("""\nPlease enter the type of scan you would like to run:
1)SYN ACK Scan
2)UDP Scan
3)Comprehensive Scan
""")

print("You have selected option: ", response)

if response == '1':
	print("Nmap Version: ", scanner.nmap_version())
	scanner.scan(ip_address, '1-1024', '-v -sS')
	print(scanner.scaninfo())
	print("IP Status: ", scanner[ip_address].state())
	print(scanner[ip_address].all_protocols())
	print("Open Ports: ", scanner[ip_address]['tcp'].keys())
elif response == '2':
	print("Nmap Version:", scanner.nmap_version())
	scanner.scan(ip_address, '1-10', '-v -sU')
	print(scanner.scaninfo())
	print("IP Status: ", scanner[ip_address].state())
	print(scanner[ip_address].all_protocols())
	print("Open Ports: ", scanner[ip_address]['udp'].keys())
elif response == '3':
	print("Nmap Version:", scanner.nmap_version())
	scanner.scan(ip_address, '1-1024', '-v -sS -sV -sC -A -O')
	print(scanner.scaninfo())
	print("IP Status: ", scanner[ip_address].state())
	print(scanner[ip_address].all_protocols())
	print("Open Ports: ", scanner[ip_address]['tcp'].keys())
	print("Operating System: ", scanner[ip_address]['osmatch'][0])
else:
	print("Please enter a valid option")
