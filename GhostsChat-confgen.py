#!/usr/bin/python3
from argparse import ArgumentParser
from sys import exit
from os import mkdir
import json

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization


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
                                                    ░           akpalanaza v0.3.1                       
"""

W = '\033[0m'
R = '\033[31m' 
G = '\033[32m' 
O = '\033[33m' 
B = '\033[34m' 
P = '\033[35m' 
C = '\033[36m' 
GR = '\033[37m'


CLIENTS         = []
CONFNAME        = ""
CONFFOLDER      = ""
SERVERIP        = ""
SERVERPORT      = ""


# +------------------------------+
# |          Encryption          |
# +------------------------------+

def RsaGenKey() -> tuple[bytes, bytes]:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key =  public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key, public_key

def RsaGetKeyBytes(key) -> bytes:
    return bytes(key)

def RsaGetKeyStr(key=bytes) -> str:
    return key.decode()

    
# +------------------------------+
# |            File              |
# +------------------------------+
    
def CreateServerConf():
    global CONFNAME, CONFFOLDER, SERVERIP, SERVERPORT
    file = CONFFOLDER + "/" + CONFNAME + ".server.ghosts"
    with open(file, "w") as f:
        payload = {
            "server" : {
                "ip" : SERVERIP,
                "port" : SERVERPORT
            }
        }

        data = json.dumps(payload)
        
        f.write(data)

    print ("++SERVER CONF CREATED++")    


def CreateClientsConf():
    global CONFNAME, CONFFOLDER, SERVERIP, SERVERPORT, CLIENTS

    arr = []

    for i in CLIENTS:
        index = CLIENTS.index(i)

        client = json.loads(i)
        client[str(index)]["privkey"] = None
        arr.append(client)

    for i in CLIENTS:
        index = CLIENTS.index(i)
        client = json.loads(i)
        nickname = client[str(index)]["nickname"]
        PRIVKEY = client[str(index)]["privkey"]
        PUBKEY = client[str(index)]["pubkey"]
        
        file = CONFFOLDER + "/" + CONFNAME + "." + nickname + ".ghosts"
        with open(file, "w") as f:
            payload = {
                "server" : {
                    "ip" : SERVERIP,
                    "port" : SERVERPORT
                },
                "user" : {
                    "nickname" : nickname,
                    "aeskey" : AESKEY,
                    "privkey" : PRIVKEY,
                    "pubkey" : PUBKEY,
                },
                "clients" : arr
            }

            data = json.dumps(payload)
            
            f.write(data)




# +------------------------------+
# |            Main              |
# +------------------------------+

if __name__ == "__main__":
    print (banner)

    print ("**SERVER CONFIGURATION**")
    CONFNAME = input("Name of configuration: ")
    CONFFOLDER = CONFNAME + ".ghosts"
    mkdir(CONFFOLDER)
    print ("++FOLDER CREATED SUCCESSFULLY++")
    SERVERIP = input("Server listening ip [must be x.x.x. not domain]: ")
    SERVERPORT = input("Server listening port: ")

    print ("**CLIENTS CONFIGURATION**")
    client_count = input("Amount of client to generate [defautl is 1]: ")
    AESKEY = input("Plain-text AES key to use [must 16, 18 or 20 chars long]: ")

    if client_count == "": client_count = 1
    else: client_count = int(client_count)

    for i in range(client_count):
        print (f"**CLIENT {i}**")
        NICKNAME = input("Nickname for client: ")
        RSAPRIV, RSAPUB = RsaGenKey()

        payload = {
            str(i) : {
                "nickname": NICKNAME,
                "pubkey" : RsaGetKeyStr(RSAPUB),
                "privkey" : RsaGetKeyStr(RSAPRIV)
            }
        }

        data = json.dumps(payload)
    
        CLIENTS.append(data)

        print ("++USER CREATED SUCCESSFULLY++")

    CreateServerConf()

    CreateClientsConf()

