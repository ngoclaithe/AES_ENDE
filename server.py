import os
import tkinter as tk
from tkinter import filedialog, messagebox
import aes128
import socket
import threading

def decrypt_file():
    input_path = input_path_var.get()
    key = key_var.get()

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

        decrypted_data = []
        temp = []
        for byte in data:
            temp.append(byte)
            if len(temp) == 16:
                decrypted_part = aes128.decrypt(temp, key)
                decrypted_data.extend(decrypted_part)
                del temp[:] 
        else:
            #padding v1
            # decrypted_data.extend(temp)
            
            # padding v2
            if 0 < len(temp) < 16:
                empty_spaces = 16 - len(temp)
                for i in range(empty_spaces - 1):
                    temp.append(0)
                temp.append(1)
                decrypted_part = aes128.encrypt(temp, key)
                decrypted_data.extend(crypted_part)

    out_path = os.path.join(os.path.dirname(input_path), 'decrypted_' + os.path.basename(input_path))
    with open(out_path, 'xb') as ff:
        ff.write(bytes(decrypted_data))

    messagebox.showinfo("Success", "Decryption completed successfully.\nNew file created at: " + out_path)

def select_file():
    file_path = filedialog.askopenfilename()
    input_path_var.set(file_path)

def start_server(server_ip='127.0.0.1', server_port=12345):
    def server_thread():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((server_ip, server_port))
            s.listen()
            conn, addr = s.accept()
            with open("server_rev.txt", 'wb') as f:
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    f.write(data)
                    
    server_thread = threading.Thread(target=server_thread)
    server_thread.start()

# GUI
root = tk.Tk()
root.title("File Decryption Server")

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

button_process = tk.Button(root, text="Decrypt", command=decrypt_file)
button_process.grid(row=2, column=0, columnspan=3, pady=10)

button_start_server = tk.Button(root, text="Start Server", command=lambda: start_server())
button_start_server.grid(row=3, column=0, columnspan=3, pady=10)

root.mainloop()
