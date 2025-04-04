import socket
import os
import threading
from client import Client
from encryption_algorithms import encrypt_AES, decrypt_AES, derive_keys, verify_hmac

clients = []

def authenticate_client(client_socket):
    # Authenticate ATM user to bank server
    data = client_socket.recv(1024)
    if not data:
        print('Client disconnected')
    nonce, tag, cipher = extract_data(data)
    plaintext = decrypt_AES(nonce, tag, cipher)
    # Authenticate bank server by answering challenge
    username, password, new_user, challenge = plaintext.split('||', 3)
    index = -1
    # Adding a new user
    if new_user == 'y': 
        index = add_user(username, password)
        if index < 0:
            plaintext = f'Error: Username already in use {username}||{challenge}'
        else:
            plaintext = f'Authenticated {username}||{challenge}'
            print(f"User '{username}' authenticated to bank server (new user).")
            print("Bank server authenticated to ATM.")
        nonce, tag, cipher = encrypt_AES(plaintext)
        client_socket.send(nonce + tag + cipher)
        if 'Error' in plaintext:
            return authenticate_client(client_socket)
        return index, True
    # Verifying an existing user
    else: 
        index = check_credentials(username, password)
        if index < 0:
            plaintext = f'Error: Incorrect username or password {username}||{challenge}'
        else:
            plaintext = f'Authenticated {username}||{challenge}'
            print(f"User '{username}' authenticated to bank server.")
            print("Bank server authenticated to ATM.")
        nonce, tag, cipher = encrypt_AES(plaintext)
        client_socket.send(nonce + tag + cipher)
        if 'Error' in plaintext:
            return authenticate_client(client_socket)
        return index, False

def interact(client_socket, encryption_key, mac_key, index):
    global clients
    while True:
        data = client_socket.recv(1024)
        if not data: 
            break
        
        # Print the raw encrypted data (nonce + tag + ciphertext + HMAC)
        print("Received encrypted transaction data (hex):", data.hex())
        
        nonce = data[:12]
        tag = data[12:28]
        cipher = data[28:-32]
        received_hmac = data[-32:]
        
        # Verify HMAC and print status
        if not verify_hmac(received_hmac, nonce + tag + cipher, mac_key):
            print("Error: MAC verification failed for transaction data:", data.hex())
            continue
        else:
            print("MAC verification succeeded for transaction data.")

        # Decrypt the transaction message
        request = decrypt_AES(nonce, tag, cipher, string=True, decryption_key=encryption_key)
        print("Decrypted transaction message:", request)
        
        clients[index].account_transaction(request, encryption_key, mac_key)
        
        parts = request.split(':')
        transaction_type = parts[0]
        try:
            amount = int(parts[1])
        except Exception:
            amount = None
        
        # Print protocol execution summary for each transaction
        if transaction_type == 'DEPOSIT':
            print("Transaction Protocol: Processing DEPOSIT for amount:", amount)
            clients[index].deposit(amount)
        elif transaction_type == 'WITHDRAWAL':
            print("Transaction Protocol: Processing WITHDRAWAL for amount:", amount)
            clients[index].withdraw(amount)
        elif transaction_type == 'INQUIRY':
            print("Transaction Protocol: Processing INQUIRY.")
            transactions = clients[index].get_transactions()
            try:
                for transaction in transactions:
                    client_socket.send(transaction + b'||')
                client_socket.send(b'END_OF_TRANSACTIONS')
            except Exception as e:
                print(f'Error during sending of transactions: {e}')
        else:
            print("Transaction Protocol: Unrecognized transaction type.")

def handle_client(client_socket, client_address):

    print(f'New connection from client {client_address}')
    
    try:
        
        index, new_user = authenticate_client(client_socket)

        if new_user:
            # (2) Generate and send new master secret key
            master_secret_key = os.urandom(32)
            clients[index].set_key(master_secret_key)
            print(f'Generated master secret key, {master_secret_key.hex()}')
            nonce, tag, cipher = encrypt_AES(master_secret_key)
            client_socket.send(nonce + tag + cipher)
            # (3) Derive encryption key and MAC from master secret key
            encryption_key, mac_key = derive_keys(master_secret_key)
            print(f'Derived key-set\nEncryption_key, {encryption_key.hex()} \nMac_key, {mac_key.hex()}')
        else:
            # (2) Retrieve and send new master secret key
            master_secret_key = clients[index].get_key()
            print(f'Retrieved master secret key, {master_secret_key.hex()}')
            nonce, tag, cipher = encrypt_AES(master_secret_key)
            client_socket.send(nonce + tag + cipher)
            # (3) Derive encryption key and MAC from master secret key
            encryption_key, mac_key = derive_keys(master_secret_key)
            print(f'Derived key-set\nEncryption_key, {encryption_key.hex()} \nMac_key, {mac_key.hex()}')
        
        # (4) Deposits, withdrawals, and balance inquiries
        interact(client_socket, encryption_key, mac_key, index)

    except Exception as e:
        print(f'Error during communications with client: {e}')

def extract_data(data):
    nonce = data[:12]
    tag = data[12:28]
    cipher = data[28:]
    return nonce, tag, cipher

def add_user(username, password):
    global clients
    if check_username(username) == -1: return -1
    c = Client(username, password)
    clients.append(c)
    index = len(clients) - 1
    return index

def check_username(username):
    global clients
    for client in clients:
        if client.username == username:
            return -1
    return 0

def check_credentials(username, password):
    for index, client in enumerate(clients):
        if client.username == username and client.password == password:
            return index
    return -1

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = '127.0.0.1'
    port = 8080
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f'Server, {host}, listening on port, {port}')

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            print(f'Connection established with {client_address}')
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
            client_thread.start()
    except KeyboardInterrupt:
        print("\nServer shutting down due to keyboard interrupt")
        server_socket.close()

if __name__ == '__main__':
    main()