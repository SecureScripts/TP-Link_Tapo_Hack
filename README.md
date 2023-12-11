# TP-Link_Tapo_Hack
Deceiving the Tapo app by impersonating a TP-Link device

# Authors
Vincenzo De Angelis (vincenzo.deangelis@unical.it), assistant professor at the University of Calabria & Sara Lazzaro (sara.lazzaro@unirc.it), researcher at the University of Reggio Calabria.

# Objective
Bypassing the authentication mechanism of the TP-Link Tapo app to obtain the victim’s password of their Tapo App in plaintext.

## Conditions of the attack
1.	The attacker is in the same network of the Tapo app (reachable through UDP broadcast)
and one of the following two: <br>
2a. The attacker knows the username (email address) of the victim in the Tapo app OR <br>
2b. A TP-Link device is present in the network of the attacker and the Tapo app

## APP version
Tapo Version 3.1.315

## Overview of the authentication mechanism of the Tapo App
The Tapo app uses the following discovery and authentication mechanism (with some devices). First, the app broadcast (255.255.255.255) in UDP a discovery message. A TP-Link device connected to the network responds to the application by providing some information including its IP address. The app starts a handshake mechanism by contacting the device through HTTP and providing its public key. The device answers by encrypting a symmetric key with such a public key. The app provides the credentials (username and password) encrypted with the symmetric key.

## Overview of the attack
The attacker simulates a TP-Link device and when receives the HTTP handshake, it encrypts its own symmetric key. Then, it receives the encrypted credentials and can decrypt them.

## Detailed steps of the attack

#### Step 1-OWNER parameter discover
The first step consists in finding the OWNER parameter used by the Tapo App before starting the HTTP handshake.
If the attacker knows the email address of the victim in the Tapo App (Condition 2a), the OWNER parameter is simply the MD5 digest of this email address and can be computed in Python as follows (OWNERFromMD5.py):

```python
import hashlib
TapoEmailVictim=b"EMAIL_ADDRESS_VICTIM"
OWNER = hashlib.md5(TapoEmailVictim).hexdigest().upper()
print(OWNER)
```

In the case the attacker does not know the email of the victim (Condition 2b), the OWNER parameter can be discovered by leveraging the TP-Link devices connected to the network. Indeed, they include this parameter in the plaintext answer to the broadcast request of the Tapo App. 
Then, the attack consists in simulating the UDP broadcast request of the Tapo-App to obtain the OWNER parameter from a TP-Link device. 
To do this use the Script OWNERFromDevice.py by inserting the IP address of the attacker.

```python
attackerIP = "IP_ADDRESS_ATTACKER"
attackerPort = 53353
bufferSize = 2048
```

We tested it in a network in which the TP-Link Tapo Smart Plug P110 was connected.
This is the result:

```python
stolen owner = 65C008A8F038F16A57E63F41EA51CC5B
```


#### Step 2-Deceiving the Tapo app by impersonating a TP-Link device.
The second step consists in deceiving the Tapo app by simulating the presence of a TP-Link device in the network. Specifically, this is performed by the attacker by answering the UDP broadcast request of the Tapo App thus simulating the behavior of an honest device. 
To do this, lunch the script UDPImpersonation.py by specifying the IP address of the attacker and the OWNER parameter retrieved from Step 1.

```python
attackerIP = "IP_ADDRESS_ATTACKER"
OWNER="OWNER_FROM_STEP_1"
localPort = 20002
bufferSize = 1024
```

In this script, we simulated the response of a TP-Link Tapo Smart Plug P110 (but it works without the presence of any device in the network).
The UDP response includes the following JSON:

```
udpJSONPayload={"result":{"device_id":"6447b7fc4902ab3a83f973a2767a38aa","owner":OWNER,"device_type":"SMART.TAPOPLUG","device_model":"P110(EU)","ip":attackerIP,"mac":"30-DE-4B-45-12-60","is_support_iot_cloud":False,"obd_src":"tplink","factory_default":False,"mgt_encrypt_schm":{"is_support_https":False,"encrypt_type":"AES","http_port":80,"lv":1}},"error_code":0}
```

Observe that all the parameters are fixed except for the OWNER and ATTACKER IP parameters used by the Tapo app to perform a check and start the HTTP-based handshake with the attacker device. The other relevant parameter is “lv:1” so that the victim’s password of the Tapo App is received in cleartext in the next step.

#### Step 3-Bypass the HTTP handshake to obtain the password in plaintext.
After receiving the UDP response from the attacker (see Step 2), the Tapo app starts an HTTP handshake with the attacker. First, the Tapo app sends an HTTP request including its RSA public key. Then, the attacker encrypts a symmetric (AES) key with such an RSA key and sends the result in the HTTP response. The Tapo app decrypts the AES key using the RSA private key and uses the AES key to encrypt the victim’s credentials including the password in cleartext. This message is sent through a new HTTP request to the attacker. The attacker uses the AES key to decrypt the password.
To perform this step lunch HTTPHandshakeImpersonation.py by specifying the IP address of the attacker.

```python
def run():
     attackerIP ="ATTACKER_IP_ADDRESS"
     server_address = (attackerIP, 80)
     httpd = HTTPServer(server_address, RequestHandlerHTTP)
     httpd.serve_forever()
```
The final result, reporting the victim’s password, is shown below:

```
10.0.0.113 - - [22/May/2023 10:26:16] "POST /app HTTP/1.1" 200 -
stolenpassword=Vincenzo&Sara
```

## Summary of the attack
1. Lunch either OWNERFromMD5.py or OWNERFromDevice.py to obtain the OWNER parameter. 
2. Lunch HTTPHandshakeImpersonation.py and UDPImpersonation.py (lunch a HTTP and UDP server simultaneously) 
3. Wait for the user to open the home of the Tapo App and obtain the password in the console of HTTPHandshakeImpersonation.py . 

## Observations
This attack is not a vulnerability of a specific device (it can be conducted even in the case no device is present in the network) but it concerns the authentication protocol the Tapo App uses. To solve the problem, we suggest removing the use of local traffic and relying on the cloud through TLS messages.

## Responsible Disclosure
We have responsibly disclosed the issue to the TP-Link company. They acknowledged it and confirmed that the Tapo app is now fixed.

