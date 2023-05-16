import rsa

publicKey, privateKey = rsa.newkeys(1024)

with open("serverPublicKey.pem","wb") as file:
    file.write(publicKey.save_pkcs1("PEM"))

with open("serverPrivateKey.pem","wb") as file:
    file.write(privateKey.save_pkcs1("PEM"))
    