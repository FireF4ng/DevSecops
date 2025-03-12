import socket
import errno
import tkinter as tk
import threading as tk_threading
from tkinter import scrolledtext, simpledialog
from crypto import aes_encrypt, aes_decrypt, generate_rsa_keys, rsa_encrypt, rsa_decrypt
from cryptography.hazmat.primitives import serialization

class ChatClient:
    def __init__(self, host="127.0.0.1", server_port=12345):
        self.host = host
        self.server_port = server_port

        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # RSA keys
        self.private_key, self.public_key = generate_rsa_keys()
        self.pem_public_key = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # GUI
        self.root = tk.Tk()
        self.root.title("Client")

        self.text_area = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, state=tk.DISABLED)
        self.text_area.pack()

        self.input_box = tk.Entry(self.root)
        self.input_box.pack()

        self.send_button = tk.Button(self.root, text="Send", command=self.send_message)
        self.send_button.pack()

        users_button = tk.Button(self.root, text="Users List", command=self.request_users)
        users_button.pack()

    def insert_text(self, text):
        self.text_area.config(state=tk.NORMAL)  # Enable editing
        self.text_area.insert(tk.END, text + "\n")  # Insert text
        self.text_area.config(state=tk.DISABLED)  # Disable editing
        self.text_area.see(tk.END)  # Auto-scroll to the end


    def connect(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((self.host, self.server_port))

        try:
            # Send the client’s RSA public key to the server
            self.client_socket.send(self.pem_public_key)

            # Receive the server’s RSA public key
            server_public_key_data = self.client_socket.recv(1024)
            server_public_key = serialization.load_pem_public_key(server_public_key_data)

            # Receive encrypted AES key from the server
            encrypted_aes_key = self.client_socket.recv(1024)

            # Decrypt the AES key using the client's private key
            self.aes_key = rsa_decrypt(self.private_key, encrypted_aes_key)

            # Encrypt the AES key using the server's public RSA key
            encrypted_aes_key_back = rsa_encrypt(server_public_key, self.aes_key)

            # Send the encrypted AES key back to the server
            self.client_socket.send(encrypted_aes_key_back)

            # Ask username
            self.name = simpledialog.askstring("Username", "Enter your username:", parent=self.root)
            if self.name:  # Ensure username is not None
                self.client_socket.send(self.name.encode('utf-8'))

            self.root.title(f"Client - {self.name}")

            self.insert_text(f"[+] Connected to server [{self.host}:{self.server_port}]")

            self.receive_thread = tk_threading.Thread(target=self.receive_messages, daemon=True)
            self.receive_thread.start()
        except Exception as e:
            self.insert_text(f"[-] Connection Error: {e}")
            self.client_socket.close()

    def encrypt(self, message):
        return aes_encrypt(message, self.aes_key)

    def decrypt(self, encrypted_message):
        return aes_decrypt(encrypted_message, self.aes_key)

    def send_message(self):
        message = self.input_box.get()
        if message:
            self.insert_text(f"[{self.name}/Me]: {message}")
            encrypted_message = self.encrypt(message)
            self.client_socket.send(encrypted_message.encode())
            self.input_box.delete(0, tk.END)

    def receive_messages(self):
        while True:
            try:
                encrypted_message = self.client_socket.recv(1024).decode()
                if not encrypted_message:
                    self.insert_text("[Info] Disconnected")
                    break
                msg = self.decrypt(encrypted_message)
                self.insert_text(f"{msg}")
            except socket.error as e:
                if e.errno == errno.WSAECONNRESET:  # WinError 10054
                    self.insert_text("[Warning] Client connection forcibly closed")
                    break
                self.insert_text(f"[Error] Socket error: {e}")
            except Exception as e:
                self.insert_text(f"[Error] Failed to decrypt: {e}")

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
