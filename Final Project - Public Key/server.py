import rsa,os,sys,hashlib,hmac
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
#read message to be sent to client
#use os.path.join to open file from the same folder/directory
with open(os.path.join(sys.path[0],"message.txt"),"r") as f:
    message = f.read()

#get the client public key
with open(os.path.join(sys.path[0],"clientPublicKey.pem"),"rb") as f:
    clientPublicKey = rsa.PublicKey.load_pkcs1(f.read())

#generate random AES Key
aesKey = b"GoneWithTheWind4600!"
print("AES Key:",aesKey)
cipher = AES.new(aesKey,AES.MODE_EAX)
#encrypt message with AES key
encrypted_message, tag = cipher.encrypt_and_digest(message.encode())
#nonce = cipher.nonce
print("Encrypted Message:",encrypted_message)

#encrypt AES key with client public key
fileKey = rsa.encrypt(aesKey,clientPublicKey)
print("fileKey:",fileKey)

#fucntion to compute HMAC
def calc_digest(key,message):
    #key = bytes(key,'utf-8')
    message = bytes(message,'utf-8')
    dig = hmac.new(key,message,hashlib.sha256)
    return dig.hexdigest()

#compute an HMAC
mac = calc_digest(aesKey,message)
print("HMAC:",mac)

#write encrypted message to file
with open(os.path.join(sys.path[0],"encryptedMessage.txt"),"wb") as f:
    f.write(encrypted_message)
#add \n separator for parsing
with open(os.path.join(sys.path[0],"encryptedMessage.txt"),"a") as f:
    f.write("\n")
#write encrypted AES key to file
with open(os.path.join(sys.path[0],"encryptedMessage.txt"),"ab") as f:
    f.write(fileKey)
    
#write HMAC to file
with open(os.path.join(sys.path[0],"encryptedMessage.txt"),"a") as f:
    f.write("\n"+mac)