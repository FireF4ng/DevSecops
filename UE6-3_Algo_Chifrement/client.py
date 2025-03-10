import socket
import tkinter as tk
import threading as tk_threading
from tkinter import scrolledtext, simpledialog
from crypto import aes_encrypt, aes_decrypt, derive_key

class ChatClient:
    def __init__(self, host="127.0.0.1", port=12345, use_aes=True):
        self.host = host
        self.port = port
        self.use_aes = use_aes  # AES by default
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.root = tk.Tk()
        self.root.title("Client")

        self.text_area = scrolledtext.ScrolledText(self.root, wrap=tk.WORD)
        self.text_area.pack()

        self.input_box = tk.Entry(self.root)
        self.input_box.pack()

        self.send_button = tk.Button(self.root, text="Envoyer", command=self.send_message)
        self.send_button.pack()

        users_button = tk.Button(self.root, text="Liste des utilisateurs", command=self.request_users)
        users_button.pack()

    def connect(self):
        try:
            self.client_socket.connect((self.host, self.port))

            # AES-based key exchange (same salt as server)
            key_str = "shared_secret"
            salt = b'fixed_salt_1234'  # Same salt as server
            self.aes_key, _ = derive_key(key_str, salt)

            name = simpledialog.askstring("Nom", "Entrez votre nom :", parent=self.root)
            self.client_socket.send(name.encode())

            self.text_area.insert(tk.END, "[+] Connecté au serveur\n")

            self.receive_thread = tk_threading.Thread(target=self.receive_messages, daemon=True)
            self.receive_thread.start()
        except Exception as e:
            self.text_area.insert(tk.END, f"[-] Erreur de connexion : {e}\n")

    def encrypt(self, message):
        return aes_encrypt(message, self.aes_key)

    def decrypt(self, encrypted_message):
        return aes_decrypt(encrypted_message, self.aes_key)

    def send_message(self):
        message = self.input_box.get()
        if message:
            self.text_area.insert(tk.END, f"[Moi]: {message}\n")
            encrypted_message = self.encrypt(message)
            self.client_socket.send(encrypted_message.encode())
            self.input_box.delete(0, tk.END)

    def receive_messages(self):
        while True:
            try:
                encrypted_message = self.client_socket.recv(1024).decode()
                if not encrypted_message:
                    break

                try:
                    msg = self.decrypt(encrypted_message)
                    self.text_area.insert(tk.END, msg + "\n")
                except Exception as e:
                    self.text_area.insert(tk.END, f"[Error] Failed to decrypt: {e}\n")
            except Exception as e:
                self.text_area.insert(tk.END, f"[-] Erreur de réception : {e}\n")
                break

    def request_users(self):
        """Request the list of users from the server."""
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
    client = ChatClient(use_aes=True)
    client.start()