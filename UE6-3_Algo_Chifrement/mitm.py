import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
from crypto import generate_dh_keys, compute_shared_secret

MITM_PORT = 5555
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 12345

class MITMProxy:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("MITM Proxy")

        self.text_area = scrolledtext.ScrolledText(self.root, wrap=tk.WORD)
        self.text_area.pack()

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(("0.0.0.0", MITM_PORT))
        self.server_socket.listen(5)

    def log(self, message):
        # Safely send log messages to the Tkinter thread
        self.root.after(0, lambda: self.text_area.insert(tk.END, f"{message}\n"))
        self.root.after(0, self.text_area.see, tk.END)

    def relay(self, source, destination, name=""):
        try:
            while True:
                data = source.recv(1024)
                if not data:
                    break
                self.log(f"[MITM] {name} -> {data.decode()}")
                destination.send(data)
        except Exception as e:
            self.log(f"[MITM] Connection error ({name}): {e}")
        finally:
            source.close()
            destination.close()

    def handle_client(self, client_socket):
        try:
            # Connect to the actual server
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((SERVER_HOST, SERVER_PORT))

            self.log("[MITM] Connection established between client and server.")

            # Start bidirectional relay
            threading.Thread(target=self.relay, args=(client_socket, server_socket, "Client -> Server"), daemon=True).start()
            threading.Thread(target=self.relay, args=(server_socket, client_socket, "Server -> Client"), daemon=True).start()

        except Exception as e:
            self.log(f"[MITM] Error handling client: {e}")

    def start(self):
        self.log(f"[*] MITM listening on port {MITM_PORT}...")
        while True:
            client_socket, _ = self.server_socket.accept()
            threading.Thread(target=self.handle_client, args=(client_socket,), daemon=True).start()

if __name__ == "__main__":
    mitm = MITMProxy()
    threading.Thread(target=mitm.start, daemon=True).start()
    mitm.root.mainloop()
