import hmac
import hashlib
from encryption_algorithms import encrypt_AES, decrypt_AES

class Client:
    
    def __init__(self, username, password, master_secret_key=None, balance=0.0,):
        self.username = username
        self.password = password
        self.balance = balance
        self.master_secret_key = master_secret_key
        self.transactions = []
        nonce, tag, cipher = encrypt_AES('BALANCE:0')
        self.transactions.append(nonce + tag + cipher)

    def account_transaction(self, transaction, encryption_key=None, mac_key=None):
        self.transactions.pop()
        nonce, tag, cipher = encrypt_AES(transaction, encryption_key)
        data = nonce + tag + cipher
        hmac_value = hmac.new(mac_key, data, hashlib.sha256).digest()
        self.transactions.append(data + hmac_value)
        nonce, tag, cipher = encrypt_AES(f'BALANCE:{self.balance}')
        data = nonce + tag + cipher
        hmac_value = hmac.new(mac_key, data, hashlib.sha256).digest()
        self.transactions.append(data + hmac_value)

    def set_key(self, master_secret_key):
        self.master_secret_key = master_secret_key

    def get_key(self):
        return self.master_secret_key

    def get_transactions(self):
        for transaction in self.transactions:
            print(f' Transaction Hex: {transaction.hex()}')
        print(f'Balance is {self.balance}')
        return self.transactions

    def deposit(self, amount):
        self.balance += amount

    def withdraw(self, amount):
        if amount < self.balance: self.balance -= amount
        else: self.balance = 0

    
    