import socket
import threading
import random
import tkinter as tk
from tkinter import simpledialog, scrolledtext
from crypto import vigenere_encrypt, vigenere_decrypt, normalize_key

P = 23
G = 5

class SecureChatClient:
    def __init__(self, host="127.0.0.1", port=5555):
        self.host = host
        self.port = port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.key_str = None
        self.name = None

        self.root = tk.Tk()
        self.root.title("Chat sécurisé")
        self.setup_ui()

    def setup_ui(self):
        self.text_area = scrolledtext.ScrolledText(self.root, wrap=tk.WORD)
        self.text_area.pack()

        self.input_box = tk.Entry(self.root)
        self.input_box.pack()

        send_button = tk.Button(self.root, text="Envoyer", command=self.send_message)
        send_button.pack()

        users_button = tk.Button(self.root, text="Liste des utilisateurs", command=self.request_users)
        users_button.pack()

    def diffie_hellman_private(self):
        return random.randint(2, P - 2)

    def diffie_hellman_shared(self, private_key, public_key):
        return (public_key ** private_key) % P

    def connect(self):
        try:
            self.client_socket.connect((self.host, self.port))

            # Diffie-Hellman Key Exchange
            P = int(self.client_socket.recv(1024).decode())
            G = int(self.client_socket.recv(1024).decode())

            private_key = self.diffie_hellman_private()
            public_key = (G ** private_key) % P
            self.client_socket.send(str(public_key).encode())

            server_public_key = int(self.client_socket.recv(1024).decode())
            shared_key = self.diffie_hellman_shared(private_key, server_public_key)
            self.key_str = normalize_key(shared_key)

            # Get username
            self.name = simpledialog.askstring("Nom", "Entrez votre nom :", parent=self.root)
            self.root.title(f"Chat sécurisé - {self.name}")
            self.client_socket.send(self.name.encode())

            threading.Thread(target=self.receive_messages, daemon=True).start()
            self.root.mainloop()

        finally:
            self.client_socket.close()

    def send_message(self):
        message = self.input_box.get()
        if message and self.key_str:
            encrypted_message = vigenere_encrypt(message, self.key_str)
            self.client_socket.send(encrypted_message.encode())
            self.text_area.insert(tk.END, f"[{self.name}]: {message}\n")
            self.input_box.delete(0, tk.END)

    def request_users(self):
        self.client_socket.send(vigenere_encrypt("/users", self.key_str).encode())

    def receive_messages(self):
        while True:
            try:
                data = self.client_socket.recv(1024).decode()
                if not data:
                    break
                decrypted_message = vigenere_decrypt(data, self.key_str)
                self.text_area.insert(tk.END, f"{decrypted_message}\n")
            except ConnectionResetError:
                self.text_area.insert(tk.END, "[INFO]: Connexion perdue.\n")
                break

if __name__ == "__main__":
    client = SecureChatClient()
    client.connect()
