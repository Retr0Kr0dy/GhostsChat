#!/usr/bin/python3
from argparse import ArgumentParser
from threading import Thread
from time import sleep
from sys import exit
from datetime import datetime, timezone
import json, socket, re, base64, secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

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


NICKNAME    = "None"
AESKEY      = "None"
PRIVKEY     = "None"
PUBKEY      = "None"
PUBKEYS     = "None"


# +------------------------------+
# |            Misc              |
# +------------------------------+

def Encode85(element):
    return base64.b85encode(str(element).encode('utf-8'))

def Decode85(element):
    return base64.b85decode(element).decode('utf-8')

def AesEncrypt(message, aes_key):
    aesgcm = AESGCM(aes_key)
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, message, None)
    return nonce + ciphertext
    
def AesDecrypt(message, aes_key):
    aesgcm = AESGCM(aes_key)
    nonce = message[:12]
    ciphertext = message[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)

def RsaSign(message, priv_key):        
    message = message.encode("utf-8")

    digest = hashes.Hash(hashes.SHA256())
    digest.update(message)
    hash = digest.finalize()
    
    priv_key = serialization.load_pem_private_key(
        priv_key,
        password=None,
        backend=default_backend()
    )

    signature = priv_key.sign(
        hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def CheckRsaSign(message, signature, pub_key):        
    message = message.encode("utf-8")

    digest = hashes.Hash(hashes.SHA256())
    digest.update(message)
    hash = digest.finalize()

    pub_key = serialization.load_pem_public_key(
            pub_key,
            backend=default_backend()
        )
        
    try:
        pub_key.verify(
            signature,
            hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False

def RsaGetKeyBytes(key) -> bytes:
    return bytes(key)

def RsaGetKeyStr(key=bytes) -> str:
    return key.decode()


# +------------------------------+
# |               Log            |
# +------------------------------+

def log(datatype=str, value=str) -> None:
    if datatype == "E": AA = R
    if datatype == "W": AA = Y
    if datatype == "I": AA = G
    if datatype == "D": AA = P
    else: AA = C

    BB = GR

    print (f"{BB}[{AA}{datatype}{BB}] - {value}{W}")

# +------------------------------+
# |            Handling          |
# +------------------------------+

def MessageInHandle(message=str, pubkeys=list) -> None:
    data = json.loads(Decode85(message))
    
    n = data["nickname"]
    t = data["time"]
    s = data["sign"]
    m = data["message"]

    if len(m) == 0: return

    for k in pubkeys:
        v = CheckRsaSign(m, bytes(bytearray(s)), RsaGetKeyBytes(k.encode()))
        if v: break

    if v: ve = G + "Signed"
    else: ve = R + "Wrong signature"

    string = G + t + f"{W} *{ve}{W}* [{C}" + n + f"{W}] " + m + O
    
    print (string,end='')
    print ("\r\n",end="\r")
    
def MessageOutHandle(message=str, priv_key=str) -> bytes:
    TIME = str(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    SIGN = RsaSign(message, priv_key)

    payload = {
        "nickname" : NICKNAME,
        "time" : TIME,
        "sign" : [int(byte) for byte in bytearray(SIGN)],
        "message" : message
    }

    return Encode85(json.dumps(payload))
 
def SendChunks(data=bytes, client=socket.socket) -> None:
    SIZE = 4096
    TOTAL = 0
    LEN = len(data)

    while TOTAL < LEN:
        CHUNK = data[TOTAL:TOTAL+SIZE]
        SENT = client.send(CHUNK)
        if SENT == 0:
            log("E","Chunk sending failed.")
            break
        TOTAL += SENT

    if SENT == TOTAL:
        sleep(0.1)
        client.send(b"0000")

def RecieveChunks(client=socket.socket) -> bytes:
    SIZE = 4096
    TOTAL = b""

    while True:
        CHUNK = client.recv(SIZE)
        if CHUNK == b"0000":
            return TOTAL
        TOTAL += CHUNK

    return TOTAL

def SendHandle(client=socket.socket, aes_key=bytes, priv_key=bytes) -> None:
    while True:
        print(f"{O}", end="\r")
        message = input("")
        if len(message) != 0:
            payload = MessageOutHandle(message, priv_key)
            encrypted_data = AesEncrypt(payload, aes_key)

            SendChunksThread = Thread(target=SendChunks, args=(encrypted_data, client))
            SendChunksThread.start()
        
def RecieveHandle(client=socket.socket, aes_key=bytes, pubkeys=list) -> None:
    while True:
        message = RecieveChunks(client)
        if len(message) == 0:
            log("E","Server died!")
            client.close()
            exit()
        try:
            plain_data = AesDecrypt(message, aes_key)
            MessageInHandle(plain_data, pubkeys)
        except:
            log("I","Revieved malformed message.")

# +------------------------------+
# |            Checker           |
# +------------------------------+

def IsValidIp(ip):
    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    return bool(ip_pattern.match(ip))

def IsValidPort(port):
    return 0 <= port <= 65535

def HandleArgs():
    global NICKNAME

    parser = ArgumentParser(description='GhostsChat is a lightweight in mem chat room server.')

    parser.add_argument('conffile', help='Configuration file (.ghosts).')
    args = parser.parse_args()
    
    with open(args.conffile, "r") as conf:
        data = json.loads(conf.read())

        ip = data["server"]["ip"]
        port = int(data["server"]["port"])
        aes_key = bytes(data["user"]["aeskey"].encode())
        privkey = RsaGetKeyBytes(data["user"]["privkey"].encode())
        NICKNAME = data["user"]["nickname"]
        pubkeys = []
        c = 0

        log("I", "Members :\n")

        print ("\t",end="")
        for i in data["clients"]:
            pk = i[str(c)]["pubkey"]
            pubkeys.append(pk)

            print (i[str(c)]["nickname"], end=", ")

            c += 1
        print ("\n")

    return ip, port, aes_key, privkey, pubkeys


# +------------------------------+
# |            Main              |
# +------------------------------+

if __name__ == "__main__":
    print (banner)
    ip, port, aes_key, privkey, pubkeys = HandleArgs()

    log("I", f"Trying to connect to {ip}:{port}")

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect ((ip, port))

    log("I", f"Connected to {B}{ip}{C}:{B}{port}{W}")
    log("I", f"You can now type your message and press enter to send.")
    log("I", f"'Ctrl + C' to exit.")
    print ("******************GhostsChat******************")

    SendThread = Thread(target=SendHandle, args=(client, aes_key, privkey))
    RecieveThread = Thread(target=RecieveHandle, args=(client, aes_key, pubkeys))

    SendThread.start()
    RecieveThread.start()


