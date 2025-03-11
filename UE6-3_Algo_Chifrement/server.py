import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, simpledialog, Frame, LEFT
from crypto import aes_encrypt, aes_decrypt, derive_key, generate_rsa_keys, rsa_encrypt
from cryptography.hazmat.primitives import serialization


class ChatServer:
    def __init__(self, host="0.0.0.0", port=12345):
        self.host = host
        self.port = port
        self.clients = {}
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Generate RSA keys
        self.private_key, self.public_key = generate_rsa_keys()

        print(f"[RSA] Server Public Key: {self.public_key}")

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
            # Send server's RSA public key to client in PEM format
            client_socket.send(self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

            # Receive the client's public key
            client_public_key_data = client_socket.recv(1024)
            client_public_key = serialization.load_pem_public_key(client_public_key_data)

            # Generate a shared AES key (this can be done by any method, here we'll just derive it)
            aes_key, _ = derive_key("shared_secret", b'fixed_salt_1234')

            # Encrypt AES key with client's public RSA key
            encrypted_aes_key = rsa_encrypt(client_public_key, aes_key)

            # Send encrypted AES key to client
            client_socket.send(encrypted_aes_key)

            try:
                name = client_socket.recv(1024).decode('utf-8').strip()
            except UnicodeDecodeError:
                self.text_area.insert(tk.END, f"[-] Username decoding failed\n")
                return

            # Now, we should be sure the username is received properly.
            if not name:
                raise ValueError("Username cannot be empty or None.")

            self.clients[name] = (client_socket, aes_key)
            self.text_area.insert(tk.END, f"[+] {name} connected from {addr}\n")

            while True:
                encrypted_data = client_socket.recv(1024)
                if not encrypted_data:
                    break

                decrypted_message = self.decrypt(encrypted_data.decode(), aes_key)
                self.text_area.insert(tk.END, f"[{name}] {decrypted_message}\n")

                if decrypted_message == "/users":
                    self.user_list(aes_key, client_socket)

                # Handle @private messages
                elif decrypted_message.startswith("@"):
                    self.private_message(decrypted_message, name, client_socket, aes_key)

                # Broadcast messages
                else:
                    self.broadcast(f"[{name}]: {decrypted_message}", exclude=name)

        finally:
            self.clients.pop(name, None)
            client_socket.close()

    def encrypt(self, message, key):
        return aes_encrypt(message, key)

    def decrypt(self, encrypted_message, key):
        return aes_decrypt(encrypted_message, key)

    def user_list(self, aes_key, client_socket):
        user_list = "Connected Users: " + ", ".join(self.clients.keys())
        encrypted_response = self.encrypt(user_list, aes_key)
        client_socket.send(encrypted_response.encode())

    def private_message(self, decrypted_message, name, client_socket, aes_key):
        try:
            # Split target and message (handle missing space)
            parts = decrypted_message[1:].split(" ", 1)

            if len(parts) < 2:
                raise ValueError("Invalid private message format")
            target, msg = parts[0], parts[1]

            if target in self.clients:
                target_socket, target_key = self.clients[target]
                encrypted_msg = self.encrypt(f"[Private] {name}: {msg}", target_key)
                target_socket.send(encrypted_msg.encode())

            else:
                error_msg = self.encrypt(f"User {target} not found.", aes_key)
                client_socket.send(error_msg.encode())

        except Exception as e:
            self.text_area.insert(tk.END, f"[-] Private message error: {e}\n")

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
