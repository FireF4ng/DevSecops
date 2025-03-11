import socket
import tkinter as tk
import threading as tk_threading
from tkinter import scrolledtext, simpledialog
from crypto import aes_encrypt, aes_decrypt, derive_key, generate_dh_keys, compute_shared_secret

class ChatClient:
    def __init__(self, host="127.0.0.1", port=5555):
        self.host = host
        self.port = port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # GUI setup
        self.root = tk.Tk()
        self.root.title("Client")

        self.text_area = scrolledtext.ScrolledText(self.root, wrap=tk.WORD)
        self.text_area.pack()

        self.input_box = tk.Entry(self.root)
        self.input_box.pack()

        self.send_button = tk.Button(self.root, text="Send", command=self.send_message)
        self.send_button.pack()

        users_button = tk.Button(self.root, text="Users List", command=self.request_users)
        users_button.pack()

    def connect(self):
        try:
            self.client_socket.connect((self.host, self.port))

            # Receive DH parameters and server public key
            dh_params = self.client_socket.recv(1024).decode().split(",")
            P, G, server_public_key = int(dh_params[0]), int(dh_params[1]), int(dh_params[2])

            # Generate DH key pair and compute shared secret
            self.private_key, self.public_key = generate_dh_keys()
            self.client_socket.send(str(self.public_key).encode())
            shared_secret = compute_shared_secret(server_public_key, self.private_key)

            # Derive AES key from shared secret
            self.aes_key, _ = derive_key(str(shared_secret), b'fixed_salt_1234')

            self.name = simpledialog.askstring("Username", "Enter your username:", parent=self.root)
            self.client_socket.send(self.name.encode())

            self.text_area.insert(tk.END, f"[+] Connected to server [{self.host}:{self.port}]\n")

            self.receive_thread = tk_threading.Thread(target=self.receive_messages, daemon=True)
            self.receive_thread.start()
        except Exception as e:
            self.text_area.insert(tk.END, f"[-] Connection Error: {e}\n")

    def encrypt(self, message):
        return aes_encrypt(message, self.aes_key)

    def decrypt(self, encrypted_message):
        return aes_decrypt(encrypted_message, self.aes_key)

    def send_message(self):
        message = self.input_box.get()
        if message:
            self.text_area.insert(tk.END, f"[{self.name}/Me]: {message}\n")
            encrypted_message = self.encrypt(message)
            self.client_socket.send(encrypted_message.encode())
            self.input_box.delete(0, tk.END)

    def receive_messages(self):
        while True:
            try:
                encrypted_message = self.client_socket.recv(1024).decode()
                if not encrypted_message:
                    break

                msg = self.decrypt(encrypted_message)
                self.text_area.insert(tk.END, msg + "\n")
            except Exception as e:
                self.text_area.insert(tk.END, f"[Error] Failed to decrypt: {e}\n")

    def request_users(self):
        encrypted_command = self.encrypt("/users")
        self.client_socket.send(encrypted_command.encode())

    def start(self):
        self.root.protocol("WM_DELETE_WINDOW", self.close_connection)
        self.connect()
        self.root.mainloop()

    def close_connection(self):
        self.client_socket.close()
        self.root.destroy()

if __name__ == "__main__":
    client = ChatClient()
    client.start()
