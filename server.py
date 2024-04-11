import os
import tkinter as tk
from tkinter import filedialog, messagebox
from aes import AES
import socket
import threading

def decrypt_file():
    input_path = input_path_var.get()
    key_hex = None
    with open("key.txt", "r") as key_file:
        key_hex = key_file.read().strip()  
    try:
        key_bytes = bytes.fromhex(key_hex[2:])  
    except ValueError:
        messagebox.showerror("Error", "Invalid key format in key.txt. Must be in the format: 0x...")
        return
    if not os.path.isfile(input_path):
        messagebox.showerror("Error", "The specified file does not exist.")
        return

    aes_instance = AES()
    with open(input_path, 'rb') as f:
        data = f.read()
        decrypted_data = aes_instance.decrypt(data, key_bytes)

    out_path = os.path.join(os.path.dirname(input_path), 'decrypted_' + os.path.basename(input_path))
    with open(out_path, 'xb') as ff:
        ff.write(bytes(decrypted_data))

    messagebox.showinfo("Success", "Decryption completed successfully.\nNew file created at: " + out_path)

def select_file():
    file_path = filedialog.askopenfilename()
    input_path_var.set(file_path)

def start_server(server_ip='192.168.59.1', server_port=5678):
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

button_process = tk.Button(root, text="Decrypt", command=decrypt_file)
button_process.grid(row=2, column=0, columnspan=3, pady=10)

button_start_server = tk.Button(root, text="Start Server", command=lambda: start_server())
button_start_server.grid(row=3, column=0, columnspan=3, pady=10)

root.mainloop()
