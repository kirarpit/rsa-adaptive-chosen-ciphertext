import argparse
import socket
import sys
import os
import time
import hashlib
from aes import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Util.number import *
from random import randint

# Handle command-line arguments
parser = argparse.ArgumentParser()
parser.add_argument("-ip", "--ipaddress", help='ip address where the server is running', required=True)
parser.add_argument("-p", "--port", help='port where the server is listening on', required=True)
parser.add_argument("-m", "--message", help='message to send to the server', required=True)
args = parser.parse_args()

# Defining Constants
MESSAGE_LENGTH = 16
AESKey = os.urandom(16)
print "Using AES key " + ':'.join(x.encode('hex') for x in AESKey)
print "AES ", bytes_to_long(AESKey)

def getConnection():
	# Create a TCP/IP socket
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	# Connect the socket to the port where the server is listening
	server_address = (args.ipaddress, int(args.port))
	sock.connect(server_address)
	
	return sock

def sendPayload(payload):
	conn = getConnection()
	conn.sendall(payload)

	response = ""
	while 1:
		data = conn.recv(MESSAGE_LENGTH)
		if not data: break
		print "Data received length:", len(data)
		response += data

	conn.close()
	return response

# load server's public key
serverPublicKeyFileName = "serverPublicKey"
f = open(serverPublicKeyFileName,'r')
RSAPubKey = RSA.importKey(f.read())
k = (RSAPubKey.size() + 1) // 8
n = RSAPubKey.n
e = RSAPubKey.e

B = pow(2, 8 * (k - 2))
B2 = 2 * B
B3 = B2 + B

# Creating payload ( RSA(AES) + SHA256SUM(AES) + AES(m) )
pkcs = PKCS1_v1_5.new(RSAPubKey)
cipher = pkcs.encrypt(AESKey)

payload = cipher
payload += hashlib.sha256(AESKey).digest()

aes = AESCipher(AESKey)
payload += aes.encrypt("You get an A+ baby!")

print "Payload length: ",len(payload)
file_ob = open('cipher.txt', "w")
file_ob.write(''.join(x.encode('hex') for x in payload))
file_ob.close()

# Verifying by sending to server
response = sendPayload(payload)
print "Response: ", response

# Parsing Cipher
file_ob = open('cipher.txt', "r")
content = file_ob.read()

cipher = content[:256].strip()
cipher = long_to_bytes(int(cipher, 16), 128)

encryptedMessage = content[256:].strip()
encryptedMessage = long_to_bytes(int(encryptedMessage, 16))
file_ob.close()

# Attack to obtain cipher
