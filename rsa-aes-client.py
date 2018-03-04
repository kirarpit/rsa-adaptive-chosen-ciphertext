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
connCount = 0
MESSAGE_LENGTH = 16
message = "You get an A+ baby!"
AESKey = os.urandom(16)
aes = AESCipher(AESKey)
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
		#print "Data received length:", len(data)
		response += data

	conn.close()
	return response

# Verifying by sending to server
def verifyPadding(payload):
	response = sendPayload(payload)
	print "response:", response
	if response.strip() == "Invalid Padding":
		return False
	return True
	
def ceildiv(a, b):
    return -(-a // b)

def floordiv(a, b):
    return a // b

def interval(a, b):
    return range(a, b + 1)

# load server's public key
serverPublicKeyFileName = "serverPublicKey"
f = open(serverPublicKeyFileName,'r')
RSAPubKey = RSA.importKey(f.read())
pkcs = PKCS1_v1_5.new(RSAPubKey)

k = (RSAPubKey.size() + 1) // 8
n = RSAPubKey.n
e = RSAPubKey.e

B = pow(2, 8 * (k - 2))
B2 = 2 * B
B3 = B2 + B

# Creating payload ( RSA(AES) + SHA256SUM(AES) + AES(m) )
def getPayload(cipher):
	payload = cipher
	payload += hashlib.sha256(AESKey).digest()
	payload += aes.encrypt(message)
	#print "Payload length: ",len(payload)

	"""
	file_ob = open('cipher.txt', "w")
	file_ob.write(''.join(x.encode('hex') for x in payload))
	file_ob.close()
	"""
	
	return payload

cipher = pkcs.encrypt(AESKey)
print verifyPadding(getPayload(cipher))

# Parsing Cipher
"""
file_ob = open('cipher.txt', "r")
content = file_ob.read()

cipher = content[:256].strip()
cipher = long_to_bytes(int(cipher, 16), 128)

encryptedMessage = content[256:].strip()
encryptedMessage = long_to_bytes(int(encryptedMessage, 16))
file_ob.close()
"""

def pkcs_conformant(c_param, s_param):
	global connCount
	connCount += 1
	cipher = long_to_bytes((c_param * pow(s_param, e, n) % n), k)
	return verifyPadding(getPayload(cipher))

# Attack to obtain cipher
c_0 = bytes_to_long(cipher)
set_m_old = {(B2, B3 - 1)}
i = 1

s_old = 0
while True:
	if i == 1:
	    s_new = ceildiv(n, B3)
	    while not pkcs_conformant(c_0, s_new):
		s_new += 1
	    print "s value", s_new

	elif i > 1 and len(set_m_old) >= 2:
	    s_new = s_old + 1
	    while not pkcs_conformant(c_0, s_new):
		s_new += 1

	elif len(set_m_old) == 1:
	    a, b = next(iter(set_m_old))
	    found = False
	    r = ceildiv(2 * (b * s_old - B2), n)
	    while not found:
		for s in interval(ceildiv(B2 + r*n, b), floordiv(B3 - 1 + r*n, a)):
		    if pkcs_conformant(c_0, s):
			found = True
			s_new = s
			break
		r += 1

	set_m_new = set()
	for a, b in set_m_old:
	    r_min = ceildiv(a * s_new - B3 + 1, n)
	    r_max = floordiv(b * s_new - B2, n)
	    for r in interval(r_min, r_max):
		new_lb = max(a, ceildiv(B2 + r*n, s_new))
		new_ub = min(b, floordiv(B3 - 1 + r*n, s_new))
		if new_lb <= new_ub:  # intersection must be non-empty
		    set_m_new |= {(new_lb, new_ub)}

	print("Calculated new intervals set_m_new = {} in Step 3".format(set_m_new))

	if len(set_m_new) == 1:
	    a, b = next(iter(set_m_new))
	    if a == b:
		print("Calculated int: ", a)
		print("Success after {} calls to the oracle.", connCount)
		break

	i += 1
	s_old = s_new
	set_m_old = set_m_new

print "Original AESKey", bytes_to_long(AESKey)

m = long_to_bytes(a % n, k)
sep = m.find(b"\x00", 2)
DecrAESKey = m[sep+1:]

print "Decrypted AESKey", bytes_to_long(DecrAESKey)
print verifyPadding(getPayload(pkcs.encrypt(DecrAESKey)))
