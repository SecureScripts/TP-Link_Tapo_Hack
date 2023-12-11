import hashlib
TapoEmailVictim=b"EMAIL_ADDRESS_VICTIM"
OWNER = hashlib.md5(TapoEmailVictim).hexdigest().upper()
print(OWNER)





