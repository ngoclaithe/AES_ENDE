import os
import tkinter as tk
from tkinter import filedialog, messagebox
import aes128
import socket

def encrypt_file():
    input_path = input_path_var.get()
    key = key_var.get()
    server_ip = ip_var.get()
    server_port = int(port_var.get())

    if not os.path.isfile(input_path):
        messagebox.showerror("Error", "The specified file does not exist.")
        return

    if len(key) > 16:
        messagebox.showerror("Error", "The key must be less than 16 characters.")
        return

    for symbol in key:
        if ord(symbol) > 0xff or not symbol.isalnum():
            messagebox.showerror("Error", "Invalid key. Use only Latin alphabet and numbers.")
            return

    with open(input_path, 'rb') as f:
        data = f.read()

        crypted_data = []
        temp = []
        for byte in data:
            temp.append(byte)
            if len(temp) == 16:
                crypted_part = aes128.encrypt(temp, key)
                crypted_data.extend(crypted_part)
                del temp[:]
        else:
            #padding v1
            # crypted_data.extend(temp)

            # padding v2
            if 0 < len(temp) < 16:
                empty_spaces = 16 - len(temp)
                for i in range(empty_spaces - 1):
                    temp.append(0)
                temp.append(1)
                crypted_part = aes128.encrypt(temp, key)
                crypted_data.extend(crypted_part)

    out_path = os.path.join(os.path.dirname(input_path), 'crypted_' + os.path.basename(input_path))
    with open(out_path, 'xb') as ff:
        ff.write(bytes(crypted_data))

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

label_key = tk.Label(root, text="Enter Key (less than 16 characters):")
label_key.grid(row=1, column=0, sticky='w')

key_var = tk.StringVar()
entry_key = tk.Entry(root, textvariable=key_var, show='*')
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
