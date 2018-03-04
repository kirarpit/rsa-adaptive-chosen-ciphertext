import Crypto
import ast
import os
import argparse
import socket
import sys
import hashlib
from aes import *
from rsa import *
from Crypto.Util.number import *

def checkIfValidPadding(rsa, cipher):
    """
    Check if the PKCS padding is valid or not
    """
    try:
	AESEncrypted = cipher[:128]

	PaddedAESKey = rsa.decrypt(AESEncrypted)
	print "Padded length:", len(PaddedAESKey)

	# Padding the front
	PaddedAESKey = b"\x00" * (rsa.get_k() - len(PaddedAESKey)) + PaddedAESKey

	if not PaddedAESKey.startswith(b'\x00\x02'):
	    return False
	
	return True
    except:
        return False

def getSessionKey(rsa, cipher):
    """
    Get the AES session key by decrypting the RSA ciphertext
    """
    try:
        AESEncrypted = cipher[:128]
        AESKey = rsa.decrypt(AESEncrypted)

        sep = AESKey.find(b"\x00", 2)

        return AESKey[sep+1:]
    except:
        return False

def myDecrypt(rsa, cipher):
    """
    Decrypt the client message: 
    AES key encrypted by the public RSA key of the server + message encrypted by the AES key
    """
    try:
        AESKey = getSessionKey(rsa, cipher) 
        print "aes len: ", len(AESKey)

	# check hash
	if hashlib.sha256(AESKey).digest() == cipher[128:160]:
		print "hash matched"
	else:
		return False
	
        aes = AESCipher(AESKey)
        print "AES:", bytes_to_long(aes.key)

	messageEncrypted = cipher[160:]
	print "encrypted message length", len(messageEncrypted)
	message = aes.decrypt(messageEncrypted)

        return message
    except:
        return False

# Parse Command-Line Arguments
parser = argparse.ArgumentParser()
parser.add_argument("-ip", "--ipaddress")
parser.add_argument("-p", "--port")
args = parser.parse_args()

# Create TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# Bind socket to port
server_address = (args.ipaddress, int(args.port))
print >>sys.stderr, 'Starting up on: %s port %s' % server_address
sock.bind(server_address)

# Listen for incoming connections
sock.listen(10)

rsa = RSACipher()

while True:
    print >>sys.stderr, 'Waiting for a connection...' # Wait for a conneciton
    connection, client_address = sock.accept()
  
    try:
        print >>sys.stderr, 'Connection from:', client_address
        # Receive the data
        cipher = connection.recv(1024)
        print("Message Received...")

	print "message length:", len(cipher)
	if checkIfValidPadding(rsa, cipher):
		message = myDecrypt(rsa, cipher)
		if not message:
			connection.sendall("Invalid Hash")
			continue

		print "decrypted successfully!"
		print "Message Decrypted:", message
		connection.sendall(message.upper())
	else:
		connection.sendall("Invalid Padding")

    finally:
        # Clean up the connection
        connection.close()
