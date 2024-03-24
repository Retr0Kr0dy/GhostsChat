#!/usr/bin/python3
from argparse import ArgumentParser
from threading import Thread
import socket
import re
import base64

banner = """
  ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓  ██████  ▄████▄   ██░ ██  ▄▄▄     ▄▄▄█████▓
 ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒▒██    ▒ ▒██▀ ▀█  ▓██░ ██▒▒████▄   ▓  ██▒ ▓▒
▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░░ ▓██▄   ▒▓█    ▄ ▒██▀▀██░▒██  ▀█▄ ▒ ▓██░ ▒░
░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░   ▒   ██▒▒▓▓▄ ▄██▒░▓█ ░██ ░██▄▄▄▄██░ ▓██▓ ░ 
░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░ ▒██████▒▒▒ ▓███▀ ░░▓█▒░██▓ ▓█   ▓██▒ ▒██▒ ░ 
 ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░   ▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░ ▒ ░░▒░▒ ▒▒   ▓▒█░ ▒ ░░   
  ░   ░  ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░    ░ ░▒  ░ ░  ░  ▒    ▒ ░▒░ ░  ▒   ▒▒ ░   ░    
░ ░   ░  ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░      ░  ░  ░  ░         ░  ░░ ░  ░   ▒    ░      
      ░  ░  ░  ░    ░ ░        ░                 ░  ░ ░       ░  ░  ░      ░  ░        
                                                    ░           akpalanaza v0.2.5 (0.3.1)                      
"""

#color console
W = '\033[0m'
R = '\033[31m' 
G = '\033[32m' 
O = '\033[33m' 
B = '\033[34m' 
P = '\033[35m' 
C = '\033[36m' 
GR = '\033[37m'


# Simily in memory DB
user_LST		= []
client_LST		= []
#aes_key_LST		= []
#rsa_key_LST		= []
#msg_history_LST = []
#files_tran_LST	= []



# +------------------------------+
# |            Misc              |
# +------------------------------+

def AddElementToList(element, list):
	list.append(base64.b85encode(element.encode('utf-8')))

def GetIdOfElement(element, list):
	return list.index(base64.b85encode(element.encode('utf-8')))

def GetElementFromList(id, list):
	return base64.b85decode(list[id]).decode('utf-8')

def PopElementFromList(id, list):
	list.pop(id)

def Encode85(element):
	return base64.b85encode(str(element).encode('utf-8'))

def Decode85(element):
	return base64.b85decode(element).decode('utf-8')

def CreateListener(ip,port):
	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server.bind((ip, port))
	server.listen()

	return server

# +------------------------------+
# |            Handling          |
# +------------------------------+

def Handle(client):
	while True:
		uid = client_LST.index(client)
		message = client.recv(8192)

		if not len(message) == 0:
			#AddElementToList(str(message), msg_history_LST)

			print (f"[{P}***{W}] - New message recieved from uid: {R}{uid}{W}",end="\r")
		
			BroadcastMessage(message)
		
		else:
			client.close()
			print (f"[{R}*X*{W}] - Client connection closed: {R}{uid}{W}")
			client_LST[client_LST.index(client)] = "dead"
			exit(0)
		
def HandleIncomingConnection(server):
	while True:
		client, address = server.accept()

		client_LST.append(client)

		print (f"[{G}***{W}] - New client at : {C}{address}{W}, {GR}UID{W}: {R}{client_LST.index(client)}{W}")

		handler = Thread(target=Handle, args=(client,))
		handler.start()

def BroadcastMessage(message):
	for client in client_LST:
		if not client == "dead":
			SendToClient(message, client)

def SendToClient(message, client):
	client.send(message)

# +------------------------------+
# |            Checker           |
# +------------------------------+

def IsValidIp(ip):
    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    return bool(ip_pattern.match(ip))

def IsValidPort(port):
    return 0 <= port <= 65535

# args handler
def HandleArgs():
	parser = ArgumentParser(description='GhostsChat is a lightweight in mem chat room server.')

	parser.add_argument('ip', help='IP for the listener.')
	parser.add_argument('port', type=int, help='Port for the listener.')

	parser.add_argument('--debug', type=int, choices=[0, 1], default=0,
	                    help='Debug mode (default: 0)')

	args = parser.parse_args()

	if args.ip and args.port:
		ip = args.ip
		port = args.port
		debug_mode = args.debug

		if not IsValidIp(ip):
			print('Error: Invalid IP address format. Must be valid IP')
			exit(-1)

		if not IsValidPort(port):
			print('Error: Invalid port number. Port must be in the range 0-65535.')
			exit(-1)

		return ip, port, debug_mode
	exit(-1)

# +------------------------------+
# |            Main              |
# +------------------------------+

if __name__ == "__main__":
	print (banner)
	ip, port, debug = HandleArgs()

	server = CreateListener(ip,port)
	
	incomer = Thread(target=HandleIncomingConnection, args=(server,))
	incomer.start()

	print (f"+------------------------+\n ip\t: {P}{ip}{W}\n port\t: {P}{port}{W}\n debug\t: {P}{debug}{W}\n+------------------------+")
	print (f"[{R}***{W}] - Server listening on : {B}{ip}{C}:{B}{port}{W}")
