from cryptography.fernet import Fernet
import json

file = open('key.key','rb')
key = file.read()
file.close()

with open('userdata.json','rb') as f:
    data = f.read()

fernet = Fernet(key)
encrypted = fernet.encrypt(data)

print(encrypted)

#with open('userdata.json','wb') as f:
    #json.dump(encrypted, f)