import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, simpledialog, Frame, LEFT
from crypto import aes_encrypt, aes_decrypt, derive_key

class ChatServer:
    def __init__(self, host="0.0.0.0", port=12345, use_aes=True):
        self.host = host
        self.port = port
        self.clients = {}
        self.use_aes = use_aes  # AES by default
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.root = tk.Tk()
        self.root.title("Serveur")

        self.text_area = scrolledtext.ScrolledText(self.root, wrap=tk.WORD)
        self.text_area.pack()

        self.input_box = tk.Entry(self.root)
        self.input_box.pack()

        self.send_button = tk.Button(self.root, text="Envoyer", command=self.server_send_message)
        self.send_button.pack()

        buttons = Frame(self.root)
        buttons.pack()

        users_button = tk.Button(self.root, text="Liste des utilisateurs", command=self.users)
        users_button.pack(in_=buttons, side=LEFT)

        kick_button = tk.Button(self.root, text="Kick User", command=self.kick)
        kick_button.pack(in_=buttons, side=LEFT)

    def users(self):
        user_list = "Utilisateurs connectés: " + ", ".join(self.clients.keys())
        self.text_area.insert(tk.END, f"[Serveur]: {user_list}\n")

    def kick(self):
        target = simpledialog.askstring("Kick", "Nom de l'utilisateur à kicker :", parent=self.root)
        if target in self.clients:
            target_socket, target_key = self.clients[target]
            message = "Vous êtes kick du serveur (déconnecté)"
            encrypted_message = self.encrypt(message, target_key)
            target_socket.send(encrypted_message.encode())
            target_socket.close()
            del self.clients[target]
            self.text_area.insert(tk.END, f"[Serveur]: Utilisateur {target} déconnecté.\n")
        else:
            self.text_area.insert(tk.END, f"[Serveur]: Utilisateur {target} introuvable.\n")

    def handle_client(self, client_socket, addr):
        try:
            # AES-based key exchange (same salt as client)
            key_str = "shared_secret"
            salt = b'fixed_salt_1234'  # Same salt as client
            aes_key, _ = derive_key(key_str, salt)

            name = client_socket.recv(1024).decode().strip()
            self.clients[name] = (client_socket, aes_key)

            self.text_area.insert(tk.END, f"[+] {name} connecté depuis {addr}\n")

            while True:
                encrypted_data = client_socket.recv(1024)
                if not encrypted_data:
                    break

                try:
                    # Decrypt the received Base64 string
                    decrypted_message = self.decrypt(encrypted_data.decode(), aes_key)
                    self.text_area.insert(tk.END, f"[{name}] {decrypted_message}\n")

                    # Handle commands
                    if decrypted_message == "/users":
                        user_list = "Utilisateurs connectés: " + ", ".join(self.clients.keys())
                        encrypted_response = self.encrypt(user_list, aes_key)
                        client_socket.send(encrypted_response.encode())

                    # Private message
                    elif decrypted_message.startswith("@"):
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

                    # Broadcast to all clients
                    else:
                        for client_name, (sock, client_key) in self.clients.items():
                            if client_name != name:
                                encrypted_msg = self.encrypt(f"[{name}]: {decrypted_message}", client_key)
                                sock.send(encrypted_msg.encode())

                except Exception as e:
                    self.text_area.insert(tk.END, f"[-] Error decrypting from {name}: {e}\n")

        except Exception as e:
            self.text_area.insert(tk.END, f"[-] Erreur avec {addr}: {e}\n")
        finally:
            self.text_area.insert(tk.END, f"[-] {name} déconnecté\n")
            self.clients.pop(name, None)
            client_socket.close()

    def encrypt(self, message, key):
        return aes_encrypt(message, key)

    def decrypt(self, encrypted_message, key):
        return aes_decrypt(encrypted_message, key)

    def server_send_message(self):
        message = self.input_box.get()
        self.text_area.insert(tk.END, f"[Serveur]: {message}\n")
        for client_name, (client_socket, client_key) in self.clients.items():
            client_socket.send(self.encrypt(f"[Serveur]: {message}", client_key).encode())
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
    server = ChatServer(use_aes=True)
    server.start()