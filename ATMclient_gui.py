import tkinter as tk
from tkinter import messagebox
import socket
import threading
import os
import sys
import hmac, hashlib

from encryption_algorithms import encrypt_AES, decrypt_AES, derive_keys, verify_hmac

class ATMClientGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ATM Client")
        self.geometry("400x300")
        self.client_socket = None
        self.encryption_key = None
        self.mac_key = None
        self.master_secret_key = None
        self.create_login_frame()
    
    def create_login_frame(self):
        self.login_frame = tk.Frame(self)
        self.login_frame.pack(pady=20)

        tk.Label(self.login_frame, text="Username:").grid(row=0, column=0, sticky="e")
        self.username_entry = tk.Entry(self.login_frame)
        self.username_entry.grid(row=0, column=1, pady=5)

        tk.Label(self.login_frame, text="Password:").grid(row=1, column=0, sticky="e")
        self.password_entry = tk.Entry(self.login_frame, show="*")
        self.password_entry.grid(row=1, column=1, pady=5)

        tk.Label(self.login_frame, text="New User?").grid(row=2, column=0, sticky="e")
        self.new_user_var = tk.StringVar(value="n")
        tk.Radiobutton(self.login_frame, text="Yes", variable=self.new_user_var, value="y").grid(row=2, column=1, sticky="w")
        tk.Radiobutton(self.login_frame, text="No", variable=self.new_user_var, value="n").grid(row=2, column=1, sticky="e")

        tk.Button(self.login_frame, text="Login", command=self.handle_login).grid(row=3, column=0, columnspan=2, pady=10)

        print("Login frame created. Waiting for user input...")

    def handle_login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        new_user = self.new_user_var.get()

        if self.client_socket is None:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                self.client_socket.connect(('127.0.0.1', 8080))
                print("Connected to bank server at 127.0.0.1:8080")
            except Exception as e:
                messagebox.showerror("Connection Error", f"Could not connect to server: {e}")
                print(f"Connection error: {e}")
                return
        
        threading.Thread(target=self.authenticate_bank, args=(username, password, new_user), daemon=True).start()
    
    def authenticate_bank(self, username, password, new_user):
        try:
            challenge = os.urandom(16)
            plaintext = f'{username}||{password}||{new_user}||{challenge.hex()}'
            nonce, tag, cipher = encrypt_AES(plaintext)
            print("Sending authentication message...")
            self.client_socket.send(nonce + tag + cipher)

            data = self.client_socket.recv(1024)
            if not data:
                self.show_error("No response from bank. Please try again.")
                print("No data received during authentication.")
                return

            nonce, tag, cipher = self.extract_data(data)
            response_plaintext = decrypt_AES(nonce, tag, cipher)
            print("Received authentication response:", response_plaintext)
            try:
                message, challenge_received = response_plaintext.split('||', 1)
            except Exception as e:
                self.show_error("Malformed response from bank.")
                print("Error splitting response:", e)
                return

            if "Error" in message:
                if "Incorrect username" in message:
                    self.show_error("Login FAILED, incorrect username or password")
                    print("Authentication error from bank: Login FAILED, incorrect username or password")
                else:
                    self.show_error(message)
                    print("Authentication error from bank:", message)
                return

            if challenge.hex() != challenge_received:
                self.show_error("Bank authentication failed! Challenge mismatch.")
                print("Challenge mismatch: expected", challenge.hex(), "but got", challenge_received)
                return

            print("Bank authenticated successfully.")

            data = self.client_socket.recv(1024)
            nonce, tag, cipher = self.extract_data(data)
            master_secret_key = decrypt_AES(nonce, tag, cipher, string=False)
            self.master_secret_key = master_secret_key
            print("Received master secret key:", master_secret_key.hex())

            self.encryption_key, self.mac_key = derive_keys(master_secret_key)
            print("Derived key-set: \n Encryption key:", self.encryption_key.hex(), "\n MAC key:", self.mac_key.hex())

            self.after(0, self.create_main_menu_frame)
        except Exception as e:
            self.show_error(f"Authentication exception: {e}")
            print("Exception during authentication:", e)

    def extract_data(self, data):
        nonce = data[:12]
        tag = data[12:28]
        cipher = data[28:]
        return nonce, tag, cipher

    def create_main_menu_frame(self):
        self.login_frame.destroy()
        self.menu_frame = tk.Frame(self)
        self.menu_frame.pack(pady=20)

        tk.Label(self.menu_frame, text="ATM Main Menu", font=("Helvetica", 14)).pack(pady=10)
        tk.Button(self.menu_frame, text="Deposit", command=self.deposit).pack(fill='x', padx=20, pady=5)
        tk.Button(self.menu_frame, text="Withdrawal", command=self.withdrawal).pack(fill='x', padx=20, pady=5)
        tk.Button(self.menu_frame, text="Account Inquiry", command=self.account_inquiry).pack(fill='x', padx=20, pady=5)
        tk.Button(self.menu_frame, text="Exit", command=self.quit).pack(fill='x', padx=20, pady=5)

        print("Switched to main menu.")

    def deposit(self):
        amount = self.simple_input("Deposit", "Enter deposit amount:")
        if amount is None:
            return
        try:
            amount = int(amount)
        except ValueError:
            messagebox.showerror("Error", "Invalid amount")
            print("Invalid deposit amount entered.")
            return
        deposit_msg = f"DEPOSIT:{amount}"
        nonce, tag, cipher = encrypt_AES(deposit_msg, self.encryption_key)
        data = nonce + tag + cipher
        hmac_value = hmac.new(self.mac_key, data, hashlib.sha256).digest()
        self.client_socket.send(data + hmac_value)
        messagebox.showinfo("Deposit", "Deposit request sent.")
        print("Deposit request sent for amount:", amount)
    
    def withdrawal(self):
        amount = self.simple_input("Withdrawal", "Enter withdrawal amount:")
        if amount is None:
            return
        try:
            amount = int(amount)
        except ValueError:
            messagebox.showerror("Error", "Invalid amount")
            print("Invalid withdrawal amount entered.")
            return
        withdrawal_msg = f"WITHDRAWAL:{amount}"
        nonce, tag, cipher = encrypt_AES(withdrawal_msg, self.encryption_key)
        data = nonce + tag + cipher
        hmac_value = hmac.new(self.mac_key, data, hashlib.sha256).digest()
        self.client_socket.send(data + hmac_value)
        messagebox.showinfo("Withdrawal", "Withdrawal request sent.")
        print("Withdrawal request sent for amount:", amount)
    
    def account_inquiry(self):
        inquiry_msg = "INQUIRY:0"
        nonce, tag, cipher = encrypt_AES(inquiry_msg, self.encryption_key)
        data = nonce + tag + cipher
        hmac_value = hmac.new(self.mac_key, data, hashlib.sha256).digest()
        self.client_socket.send(data + hmac_value)
        print("Account inquiry request sent.")
        threading.Thread(target=self.receive_transactions, daemon=True).start()
    
    def receive_transactions(self):
        received_data = b""
        while True:
            try:
                chunk = self.client_socket.recv(1024)
                if not chunk:
                    print("Connection closed unexpectedly during inquiry.")
                    break
                if b'END_OF_TRANSACTIONS' in chunk:
                    received_data += chunk
                    break
                received_data += chunk
            except Exception as e:
                print("Error during receiving transactions:", e)
                self.show_error(f"Error receiving transactions: {e}")
                return

        transactions = received_data.split(b'||')[:-1]
        balance_str = None
        other_transactions = []

        for transaction in transactions:
            nonce = transaction[:12]
            tag = transaction[12:28]
            cipher = transaction[28:-32]
            received_hmac = transaction[-32:]
            if not verify_hmac(received_hmac, nonce + tag + cipher, self.mac_key):
                other_transactions.append("MAC verification failed for a transaction.")
                continue

            request = decrypt_AES(nonce, tag, cipher, string=True, decryption_key=self.encryption_key)
            if request.startswith("BALANCE:"):
                balance_str = request
            else:
                # For inquiries just show INQUIRY
                if request.startswith("INQUIRY:"):
                    request = "INQUIRY"
                other_transactions.append(request)
        
        # Update the inquiry window with balance and transactions
        self.after(0, lambda: self.show_transactions(balance_str, "\n".join(other_transactions)))
    
    def show_transactions(self, balance, transactions_text):
        top = tk.Toplevel(self)
        top.title("Account Inquiry")
        
        # Create a frame for the balance display (at the top)
        balance_frame = tk.Frame(top)
        balance_frame.pack(pady=10)
        if balance:
            # Display the balance (at the top)
            balance_label = tk.Label(balance_frame, text=balance, font=("Helvetica", 16, "bold"))
            balance_label.pack()
        else:
            balance_label = tk.Label(balance_frame, text="Balance: N/A", font=("Helvetica", 16, "bold"))
            balance_label.pack()
        
        # Create a frame for the transactions
        transactions_frame = tk.Frame(top)
        transactions_frame.pack(padx=10, pady=10, fill="both", expand=True)
        transactions_text_widget = tk.Text(transactions_frame, wrap='word', width=50, height=15)
        transactions_text_widget.pack(fill="both", expand=True)
        transactions_text_widget.insert('end', transactions_text)
        transactions_text_widget.config(state='disabled')
        
        print("Account transactions received and displayed.")
    
    def simple_input(self, title, prompt):
        input_window = tk.Toplevel(self)
        input_window.title(title)
        tk.Label(input_window, text=prompt).pack(padx=10, pady=10)
        entry = tk.Entry(input_window)
        entry.pack(padx=10, pady=10)
        result = []
        def on_submit():
            result.append(entry.get())
            input_window.destroy()
        tk.Button(input_window, text="Submit", command=on_submit).pack(pady=10)
        self.wait_window(input_window)
        return result[0] if result else None
    
    def show_error(self, message):
        self.after(0, lambda: messagebox.showerror("Error", message))
        print("Error:", message)

if __name__ == "__main__":
    app = ATMClientGUI()
    app.mainloop()