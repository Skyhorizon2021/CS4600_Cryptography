import rsa,os,sys,hashlib,hmac

#Pre-shared key with server
sharedKey = "GoneWithTheWind4600!"

#get the client private key to decrypt message
with open(os.path.join(sys.path[0],"clientPrivateKey.pem"),"rb") as f:
    clientPrivateKey = rsa.PrivateKey.load_pkcs1(f.read())
    
#get the data encrypted message from server
with open(os.path.join(sys.path[0],"encryptedMessage.txt"),"rb") as f:
    data = f.readlines()
    encryptedMessage = data[0].strip()
    mac = data[1]
#decrypt message 
plaintext = rsa.decrypt(encryptedMessage,clientPrivateKey)
print("Message Received:",plaintext.decode())

#function to verify message integrity
def verifyHMAC(key, message,mac):
    key = bytes(key,'utf-8')
    #compute a comparison HMAC based on decrypted plaintext and pre-shared key
    dig = hmac.new(key,message,hashlib.sha256).hexdigest().encode()
    print("Computed HMAC",dig)
    print("Received HMAC",mac)
    return hmac.compare_digest(mac,dig)

#call function to verify message integrity
if verifyHMAC(sharedKey,plaintext,mac) == True:
    print("Message Authenticated Successfully!")
else:
    print("Message Not Authenticated!")






#mac = data[1].decode()