import rsa
from Crypto.Cipher import AES

publicKey, privateKey = rsa.newkeys(1024)

with open("serverPublicKey.pem","wb") as file:
    file.write(publicKey.save_pkcs1("PEM"))

with open("serverPrivateKey.pem","wb") as file:
    file.write(privateKey.save_pkcs1("PEM"))

with open("aesFileKey.pem","wb") as file:
    file.write(fileKey.save_pkcs1("PEM"))