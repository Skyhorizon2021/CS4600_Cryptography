import rsa,os,sys,hashlib,hmac

#read message to be sent to client
#use os.path.join to open file from the same folder/directory
with open(os.path.join(sys.path[0],"message.txt"),"r") as f:
    message = f.read()

#get the client public key
with open(os.path.join(sys.path[0],"clientPublicKey.pem"),"rb") as f:
    clientPublicKey = rsa.PublicKey.load_pkcs1(f.read())


#encrypt message with client public key 
encrypted_message = rsa.encrypt(message.encode(),clientPublicKey)

#fucntion to compute HMAC
def calc_digest(key,message):
    key = bytes(key,'utf-8')
    message = bytes(message,'utf-8')
    dig = hmac.new(key,message,hashlib.sha256)
    return dig.hexdigest()

#compute an HMAC
mac = calc_digest('GoneWithTheWind4600!',message)
print(mac)

#write encrypted message to file
with open(os.path.join(sys.path[0],"encryptedMessage.txt"),"wb") as f:
    f.write(encrypted_message)
    
#write HMAC to file
with open(os.path.join(sys.path[0],"encryptedMessage.txt"),"a") as f:
    f.write("\n"+mac)