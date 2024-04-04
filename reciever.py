import socket
import tqdm
from Crypto.Cipher import AES

key = b"TheDarkVenom_Key"
nonce = b"TheDarkVenom_Nce"

cipher = AES.new(key, AES.MODE_EAX, nonce)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server.bind(("localhost", 4444))
server.listen()

client, addr = server.accept()

# Recieve data
filename = client.recv(1024).decode()
print("Recieving File: " + filename)
filesize = client.recv(1024).decode()
print("File size: " + filesize)

file = open(filename, "wb")

done = False
file_bytes = b""

progress = tqdm.tqdm(unit="B", unit_scale=True, unit_divisor=1000, total=int(filesize))
try:
    while not done:
        data = client.recv(1024)
        if file_bytes[-5:] == b"<END>":
            done = True
        else:
            file_bytes += data
        progress.update(1024)
except KeyboardInterrupt as k:
    print("\nKeyboard interrupt occurred...Stoping file transfer...")
    print(k)
    file.close()
    client.close()
    server.close()
except ConnectionError as ce:
    print("\nConnection error occurred...")
    print(ce)

file.write(cipher.decrypt(file_bytes))

file.close()
client.close()
server.close()
print()
print("File recieved successfully...!")






