import os
import tkinter as tk
from tkinter import filedialog, messagebox
from aes import AES
import socket
def genkey(key_length):
    if key_length == 128:
        bit = 128
    elif key_length == 192:
        bit = 192
    elif key_length == 256:
        bit = 256
    else:
        raise ValueError("Invalid key length. Use only 128, 192, or 256.")

    key = os.urandom(bit// 8)
    return key
def encrypt_file():
    input_path = input_path_var.get()
    key_length = key_var.get()
    server_ip = ip_var.get()
    server_port = int(port_var.get())

    if not os.path.isfile(input_path):
        messagebox.showerror("Error", "The specified file does not exist.")
        return
    key = genkey(key_length)
    key_hex = key.hex()
    aes_instance = AES()


    with open("key.txt", "w") as key_file:
        key_hex = '0x' + key.hex()
        key_file.write(key_hex)


    with open(input_path, 'rb') as f:
        data = f.read()
        encrypted_data = aes_instance.encrypt(data, key)

    out_path = os.path.join(os.path.dirname(input_path), 'crypted_' + os.path.basename(input_path))
    with open(out_path, 'xb') as ff:
        ff.write(bytes(encrypted_data))

    send_to_server(out_path, server_ip, server_port)

    messagebox.showinfo("Success", "Encryption completed successfully.\nNew file created at: " + out_path)

def send_to_server(file_path, server_ip, server_port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_ip, server_port))
        with open(file_path, 'rb') as f:
            while True:
                data = f.read(1024)
                if not data:
                    break
                s.sendall(data)

def select_file():
    file_path = filedialog.askopenfilename()
    input_path_var.set(file_path)

# GUI
root = tk.Tk()
root.title("File Encryption")

label_file = tk.Label(root, text="Select file:")
label_file.grid(row=0, column=0, sticky='w')

input_path_var = tk.StringVar()
entry_file = tk.Entry(root, textvariable=input_path_var, width=50)
entry_file.grid(row=0, column=1, columnspan=2, sticky='w')

button_select_file = tk.Button(root, text="Browse", command=select_file)
button_select_file.grid(row=0, column=3)

label_key = tk.Label(root, text="Enter key bit (128 or 192 or 256):")
label_key.grid(row=1, column=0, sticky='w')

key_var = tk.IntVar()  
entry_key = tk.Entry(root, textvariable=key_var, show=None) 
entry_key.grid(row=1, column=1, columnspan=2, sticky='w')

label_ip = tk.Label(root, text="Enter Server IP:")
label_ip.grid(row=2, column=0, sticky='w')

ip_var = tk.StringVar()
entry_ip = tk.Entry(root, textvariable=ip_var)
entry_ip.grid(row=2, column=1, columnspan=2, sticky='w')

label_port = tk.Label(root, text="Enter Port:")
label_port.grid(row=3, column=0, sticky='w')

port_var = tk.StringVar()
entry_port = tk.Entry(root, textvariable=port_var)
entry_port.grid(row=3, column=1, columnspan=2, sticky='w')

button_process = tk.Button(root, text="Encrypt", command=encrypt_file)
button_process.grid(row=4, column=0, columnspan=4, pady=10)

root.mainloop()
