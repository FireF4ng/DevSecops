import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, simpledialog, Frame, LEFT
from crypto import aes_encrypt, aes_decrypt, derive_key, generate_dh_keys, compute_shared_secret

P = 23  # Prime number
G = 5   # Generator

class ChatServer:
    def __init__(self, host="0.0.0.0", port=12345):
        self.host = host
        self.port = port
        self.clients = {}
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Diffie-Hellman key pair
        self.private_key, self.public_key = generate_dh_keys()

        # GUI setup
        self.root = tk.Tk()
        self.root.title("Server")

        self.text_area = scrolledtext.ScrolledText(self.root, wrap=tk.WORD)
        self.text_area.pack()

        self.input_box = tk.Entry(self.root)
        self.input_box.pack()

        self.send_button = tk.Button(self.root, text="Send", command=self.server_send_message)
        self.send_button.pack()

        buttons = Frame(self.root)
        buttons.pack()

        users_button = tk.Button(buttons, text="User List", command=self.users)
        users_button.pack(side=LEFT)

        kick_button = tk.Button(buttons, text="Kick User", command=self.kick)
        kick_button.pack(side=LEFT)

    def users(self):
        user_list = "Connected users: " + ", ".join(self.clients.keys())
        self.text_area.insert(tk.END, f"[Server]: {user_list}\n")

    def kick(self):
        target = simpledialog.askstring("Kick", "Enter username:", parent=self.root)
        if target in self.clients:
            target_socket, target_key = self.clients[target]
            try:
                kick_msg = self.encrypt("You have been kicked.", target_key)
                target_socket.send(kick_msg.encode())
                target_socket.close()
            except:
                pass
            del self.clients[target]
            self.broadcast(f"[Server]: Kicked {target}")

    def handle_client(self, client_socket, addr):
        name = None
        try:
            # Send DH parameters and server public key
            client_socket.send(f"{P},{G},{self.public_key}".encode())

            # Receive client's public key and compute shared secret
            client_public_key = int(client_socket.recv(1024).decode())
            shared_secret = compute_shared_secret(client_public_key, self.private_key)

            # Derive AES key from shared secret
            aes_key, _ = derive_key(str(shared_secret), b'fixed_salt_1234')

            name = client_socket.recv(1024).decode().strip()
            self.clients[name] = (client_socket, aes_key)
            self.text_area.insert(tk.END, f"[+] {name} connected from {addr}\n")

            while True:
                encrypted_data = client_socket.recv(1024)
                if not encrypted_data:
                    break

                # Log the encrypted data for debugging
                self.text_area.insert(tk.END, f"[Encrypted Data] {encrypted_data}\n")

                decrypted_message = self.decrypt(encrypted_data.decode(), aes_key)
                self.text_area.insert(tk.END, f"[{name}] {decrypted_message}\n")
                self.broadcast(f"[{name}]: {decrypted_message}", exclude=name)

        finally:
            self.clients.pop(name, None)
            client_socket.close()

    def encrypt(self, message, key):
        return aes_encrypt(message, key)

    def decrypt(self, encrypted_message, key):
        return aes_decrypt(encrypted_message, key)

    def broadcast(self, message, exclude=None):
        for client_name, (sock, key) in self.clients.items():
            if client_name != exclude:
                sock.send(self.encrypt(message, key).encode())

    def server_send_message(self):
        message = self.input_box.get()
        self.text_area.insert(tk.END, f"[Server]: {message}\n")
        self.broadcast(f"[Server]: {message}")
        self.input_box.delete(0, tk.END)

    def start(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        threading.Thread(target=self.accept_connections, daemon=True).start()
        self.root.mainloop()

    def accept_connections(self):
        while True:
            client_socket, addr = self.server_socket.accept()
            threading.Thread(target=self.handle_client, args=(client_socket, addr), daemon=True).start()

if __name__ == "__main__":
    server = ChatServer()
    server.start()
