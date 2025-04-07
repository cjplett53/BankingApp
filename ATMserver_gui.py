import tkinter as tk
from tkinter import scrolledtext
import threading
import socket
import os
import sys

from ATMserver import handle_client

class ConsoleRedirector:
    def __init__(self, log_function, original_stdout):
        self.log_function = log_function
        self.original_stdout = original_stdout

    def write(self, text):
        self.original_stdout.write(text) # Write to the original stdout
        # If the text is not empty log it to the GUI
        if text.strip():
            self.log_function(text.strip())

    def flush(self):
        self.original_stdout.flush()

class ATMServerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Bank Server")
        self.geometry("600x400")
        
        # Clear the transactions file on startup
        with open("customer_transactions.txt", "w") as f:
            f.write("")
        
        # Create a scrollable text widget for logs.
        self.log_text = scrolledtext.ScrolledText(self, state='disabled', wrap='word')
        self.log_text.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Override sys.stdout so that all print messages are also sent to the GUI
        sys.stdout = ConsoleRedirector(self.log, sys.__stdout__)
        
        self.server_socket = None
        self.running = False

        # Automatically start the server when the GUI launches
        self.start_server()

    def start_server(self):
        self.running = True
        threading.Thread(target=self.run_server, daemon=True).start()
        self.log("Server started.")

    def run_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        host = '127.0.0.1'
        port = 8080
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((host, port))
        self.server_socket.listen(5)
        self.log(f"Server listening on {host}:{port}")
        try:
            while self.running:
                client_socket, client_address = self.server_socket.accept()
                self.log(f"Connection established with {client_address}")
                threading.Thread(target=self.handle_client_wrapper, args=(client_socket, client_address), daemon=True).start()
        except Exception as e:
            self.log(f"Server error: {e}")
        finally:
            self.server_socket.close()

    def handle_client_wrapper(self, client_socket, client_address):
        try:
            handle_client(client_socket, client_address)
        except Exception as e:
            self.log(f"Error with client {client_address}: {e}")
        finally:
            client_socket.close()
            self.log(f"Connection with {client_address} closed.")

    def log(self, message):
        self.after(0, lambda: self._append_log(message))

    def _append_log(self, message):
        self.log_text.config(state='normal')
        self.log_text.insert('end', message + "\n")
        self.log_text.see('end')
        self.log_text.config(state='disabled')

if __name__ == "__main__":
    app = ATMServerGUI()
    app.mainloop()