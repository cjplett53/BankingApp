import hmac
import hashlib
import datetime
from encryption_algorithms import encrypt_AES, decrypt_AES

class Client:
    def __init__(self, username, password, master_secret_key=None, balance=0.0):
        self.username = username
        self.password = password
        self.balance = balance
        self.master_secret_key = master_secret_key
        self.transactions = []
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        composite = f"{self.username}||BALANCE:{self.balance}||{timestamp}"
        nonce, tag, cipher = encrypt_AES(composite)  # Uses default key if not provided
        self.transactions.append(nonce + tag + cipher)

    def account_transaction(self, transaction, encryption_key=None, mac_key=None):
        if self.transactions:
            self.transactions.pop()
        # Build message: "username || transaction || timestamp"
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        composite = f"{self.username}||{transaction}||{timestamp}"
        nonce, tag, cipher = encrypt_AES(composite, encryption_key)
        data = nonce + tag + cipher
        hmac_value = hmac.new(mac_key, data, hashlib.sha256).digest()
        self.transactions.append(data + hmac_value)
        # Build updated record
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        composite_balance = f"{self.username}||BALANCE:{self.balance}||{timestamp}"
        nonce, tag, cipher = encrypt_AES(composite_balance, encryption_key)
        data = nonce + tag + cipher
        hmac_value = hmac.new(mac_key, data, hashlib.sha256).digest()
        self.transactions.append(data + hmac_value)

    def set_key(self, master_secret_key):
        self.master_secret_key = master_secret_key

    def get_key(self):
        return self.master_secret_key

    def get_transactions(self):
        for transaction in self.transactions:
            print(f'Transaction Hex: {transaction.hex()}')
        print(f'Balance is {self.balance}')
        return self.transactions

    def deposit(self, amount):
        self.balance += amount

    def withdraw(self, amount):
        if amount < self.balance:
            self.balance -= amount
        else:
            self.balance = 0