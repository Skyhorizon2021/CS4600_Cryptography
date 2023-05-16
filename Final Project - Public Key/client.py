import rsa

publicKey, privateKey = rsa.newkeys(1024)

with open("clientPublicKey.pem","wb") as file:
    file.write(publicKey.save_pkcs1("PEM"))

with open("clientPrivateKey.pem","wb") as file:
    file.write(privateKey.save_pkcs1("PEM"))