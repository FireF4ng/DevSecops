import socket
import threading
import logging
import tkinter as tk
from tkinter import ttk

class MITM:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server_socket = None
        self.client_connections = []
        self.client_tabs = {}

        # Set up logging
        self.logger = logging.getLogger("MITM")
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(message)s')

        # Set up the Tkinter window
        self.root = tk.Tk()
        self.root.title("MITM Monitor")
        self.root.geometry("800x600")  # Set a reasonable default window size

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True)

        # Keep track of log updates for each client
        self.client_logs = {}

    def log(self, message):
        """Log the message to the console and to the Tkinter window."""
        self.logger.info(message)

        # Update the latest log message in the Tkinter window for all clients
        for client_name, log_text in self.client_tabs.items():
            log_text.insert(tk.END, f"{message}\n")
            log_text.yview(tk.END)

    def add_client_tab(self, client_name):
        """Create a new tab for a client and a log display."""
        tab_frame = ttk.Frame(self.notebook)
        self.notebook.add(tab_frame, text=client_name)

        # Add a Text widget inside the tab for logging client interactions
        log_text = tk.Text(tab_frame, height=20, width=80)
        log_text.pack(padx=10, pady=10, expand=True, fill=tk.BOTH)

        # Save the reference to the Text widget in the client_tabs dictionary
        self.client_tabs[client_name] = log_text

    def start_server(self):
        """Start the MITM server to intercept client-server connections."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.log(f"[MITM] Listening on {self.host}:{self.port}...")

        while True:
            client_socket, client_address = self.server_socket.accept()
            self.log(f"[MITM] Accepted connection from {client_address}")
            self.handle_client(client_socket)

    def handle_client(self, client_socket):
        """Handle a new client connection."""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect(('server_address', 12345))  # Replace with actual server address & port
        self.log(f"[MITM] Connection established between client and server.")
        
        # Add a tab for the client
        client_name = f"Client {len(self.client_connections) + 1}"
        self.add_client_tab(client_name)

        # Start two-way communication: client <-> MITM <-> server
        self.client_connections.append(client_socket)
        threading.Thread(target=self.forward_data, args=(client_socket, server_socket, client_name)).start()
        threading.Thread(target=self.forward_data, args=(server_socket, client_socket, client_name)).start()

    def forward_data(self, source_socket, destination_socket, client_name):
        """Forward data between the client and server."""
        while True:
            try:
                data = source_socket.recv(4096)
                if not data:
                    break
                
                # Log data received from source (client or server)
                self.log(f"[MITM] {client_name} received: {data.decode()}")

                # Forward the data to the destination (server or client)
                destination_socket.send(data)
            except Exception as e:
                self.log(f"[MITM] Error while forwarding data: {e}")
                break

    def start(self):
        """Start the MITM server and Tkinter window."""
        # Start the MITM server in a separate thread
        threading.Thread(target=self.start_server, daemon=True).start()

        # Run the Tkinter event loop to keep the UI responsive
        self.root.after(100, self.update_ui)  # Call update_ui after every 100ms to keep the UI responsive
        self.root.mainloop()

    def update_ui(self):
        """Update the Tkinter UI by checking for new events."""
        # This prevents the Tkinter UI from freezing while waiting for logs to update
        self.root.after(100, self.update_ui)  # Ensure this keeps running

if __name__ == "__main__":
    mitm = MITM('localhost', 9999)
    mitm.start()
