import rsa,os,sys,hashlib,hmac

#get the client private key to decrypt message
with open(os.path.join(sys.path[0],"clientPrivateKey.pem"),"rb") as f:
    clientPrivateKey = rsa.PrivateKey.load_pkcs1(f.read())
    
#get the data encrypted message from server
with open(os.path.join(sys.path[0],"encryptedMessage.txt"),"rb") as f:
    data = f.readlines()
    encryptedMessage = data[0].strip()
    mac = data[1]

#decrypt message 
message = rsa.decrypt(encryptedMessage,clientPrivateKey)
print(message.decode())
#verify message integrity
#mac = data[1].decode()