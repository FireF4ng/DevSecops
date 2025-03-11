import socket
import errno
import tkinter as tk
import threading as tk_threading
from tkinter import scrolledtext, simpledialog
from crypto import aes_encrypt, aes_decrypt, derive_key, generate_dh_keys, compute_shared_secret
import time


class ChatClient:
    def __init__(self, host="127.0.0.1", server_port=12345, mitm_port=5555):
        self.host = host
        self.server_port = server_port
        self.mitm_port = mitm_port
        self.used_port = None

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
            # Try connecting to MITM proxy first
            self.client_socket.connect((self.host, self.mitm_port))
            self.used_port = self.mitm_port
        except ConnectionRefusedError:
            # Fall back to direct connection to the server
            self.client_socket.close()
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.host, self.server_port))
            self.used_port = self.server_port

        try:
            # Receive DH parameters and server public key
            dh_params = self.client_socket.recv(1024).decode().split(",")
            server_P, server_G, server_public_key = int(dh_params[0]), int(dh_params[1]), int(dh_params[2])

            # Generate DH key pair and compute shared secret
            self.private_key, self.public_key = generate_dh_keys(server_P, server_G)

            self.client_socket.send(str(self.public_key).encode())
            time.sleep(0.1)
            shared_secret = compute_shared_secret(server_public_key, self.private_key, server_P)

            # Derive AES key from shared secret
            self.aes_key, _ = derive_key(str(shared_secret), b'fixed_salt_1234')

            """Debugging
            print(f"[DH] Client public key: {self.public_key}")
            print(f"[DH] Client computed shared secret: {shared_secret}")
            print(f"[DH] Client AES key: {self.aes_key}")
            print(f"[DH] Client P: {server_P}, G: {server_G}")
            print(f"[DH] Server public key (received): {server_public_key}")
            print(f"[DH] Client private key: {self.private_key}")"
            """

            self.name = simpledialog.askstring("Username", "Enter your username:", parent=self.root)
            self.client_socket.send(self.name.encode())

            self.text_area.insert(tk.END, f"[+] Connected to server [{self.host}:{self.used_port}]\n")

            self.receive_thread = tk_threading.Thread(target=self.receive_messages, daemon=True)
            self.receive_thread.start()
        except Exception as e:
            self.text_area.insert(tk.END, f"[-] Connection Error: {e}\n")
            self.client_socket.close()

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
                    self.text_area.insert(tk.END, f"[Info] Disconnected {e}\n")
                    break
                msg = self.decrypt(encrypted_message)
                self.text_area.insert(tk.END, msg + "\n")
            except socket.error as e:
                if e.errno == errno.WSAECONNRESET:  # WinError 10054
                    self.text_area.insert(tk.END, "[Warning] Client connection forcibly closed\n")
                    break
                self.text_area.insert(tk.END, f"[Error] Socket error: {e}\n")
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
