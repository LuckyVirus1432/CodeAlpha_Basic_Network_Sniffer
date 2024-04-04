import os
import socket
import tkinter as tk
from tkinter import filedialog
from Crypto.Cipher import AES
import threading

key = b"TheDarkVenom_Key"
nonce = b"TheDarkVenom_Nce"
filename = ''
targetIP = "127.0.0.1"
port = 4444

cipher = AES.new(key, AES.MODE_EAX, nonce)

def browse_file():
    global filename
    filepath = filedialog.askopenfilename()
    filename = os.path.basename(filepath)
    if filename:
        print("Selected file:", filename)
        file_label.config(text="Selected file: " + filename)
        file_size_label.config(text="File size: " + str(os.path.getsize(filename)) + " bytes")

def get_IP_address():
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    return ip_address

def get_target_IP():
    global targetIP
    content = text.get("1.0", tk.END).strip()
    # Check if the text content is empty
    if not content:
        # If the text content is empty, set the default value
        targetIP = targetIP
    else:
        # Otherwise, extract the text content and strip any leading/trailing whitespace
        targetIP = content

    threading.Thread(target=sendFile).start()

def sendFile():
    global filename, file_size, targetIP, port
    if not filename or not os.path.exists(filename):
        error_label.config(text="Error: File not found")
        print("Error: File not found")
        return

    file_size = os.path.getsize(filename)

    done = False
    try:
        with open(filename, "rb") as f:
            data = f.read()
        encrypted_data = cipher.encrypt(data)
        
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((targetIP, port))

        print("Sending file...")
        client.send(filename.encode())
        print(f"File size: {file_size} bytes")
        client.send(str(file_size).encode())
        client.sendall(encrypted_data)
        client.send(b"<END>")  
        done = True
         
    except ConnectionRefusedError as e:
        error_label.config(text="Connection refused: No connection could be made.")
        print("Connection refused..!")
        print("No connection could be made because either the target machine actively refused it or you terminated the program")
    except Exception as e:
        print("Error occurred.")
        print("Retry...")
        print(e)
    finally:
        client.close()
    
    if done:
        success_label.config(text="File has been sent successfully...!")
        print("File sent successfully...!")



# Create a Tkinter window
root = tk.Tk()
root.configure(bg='black')
root.title("Send a file")
# root.geometry("400x300")
root.maxsize(height=500, width=600)
root.minsize(height=400, width=500)


hostIP = get_IP_address()
host_label = tk.Label(root, text=f"HostIP: {hostIP}", padx=0, bg="black", fg='yellow', font=('',15))
host_label.pack(pady=10)

choose_label = tk.Label(root, text="Choose a file to send: ", padx=0, bg="black", fg='aqua', font=('',20))
choose_label.pack(pady=10)
# Create a button for file selection
browse_button = tk.Button(root, text="Browse", command=browse_file, width=100, bg='grey', height=2)
browse_button.pack(pady=5)
# Create a label to display the selected file name
file_label = tk.Label(root, text="", bg='black', fg='white')
file_label.pack(pady=5)
file_size_label = tk.Label(root, text="", bg='black', fg='white')
file_size_label.pack(pady=5)


# Create a Label widget to display the text
text_label = tk.Label(root, text="Enter the Target IP: ", fg='aqua', bg='black', font=('',20))
text_label.pack(pady=10)
text = tk.Text(root, height=1, width=50)
text.pack()
# Create a button to get text input
text_button = tk.Button(root, text="Send", command=get_target_IP, height=2, width=30)
text_button.pack(pady=30)

success_label = tk.Label(root, text="", bg='black', fg='green')
success_label.pack(pady=5)
# Error label to display error messages
error_label = tk.Label(root, text="", bg='black', fg='red')
error_label.pack(pady=5)


# Run the Tkinter event loop
root.mainloop()