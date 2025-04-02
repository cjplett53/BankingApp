import socket
import os
import hmac
import hashlib
import sys
from encryption_algorithms import encrypt_AES, decrypt_AES, derive_keys, verify_hmac

def authenticate_bank(client_socket):
    # (1) Prompt user for username and password
    new_user, username, password = get_credentials()
    # (2) Authenticate user to bank, send challenge
    challenge = os.urandom(16)
    plaintext = f'{username}||{password}||{new_user}||{challenge.hex()}'
    nonce, tag, cipher = encrypt_AES(plaintext)
    client_socket.send(nonce + tag + cipher)
    # (2) Authenticate bank server to ATM via challenge received
    data = client_socket.recv(1024)
    nonce, tag, cipher = extract_data(data)
    plaintext = decrypt_AES(nonce, tag, cipher)
    message, challenge_received = plaintext.split('||', 2)
    if 'Error' in message: 
        print(message)
        authenticate_bank(client_socket)
    if challenge.hex() != challenge_received:
        print(f'Bank authentication failed!')
        sys.exit(1)
    print('\nBank authenticated.\n')

def get_credentials():
    new_user = input('Are you a new user? (y/n) ')
    username = input('Please enter username: ')
    password = input('Please enter password: ')
    return new_user, username, password

def extract_data(data):
    nonce = data[:12]
    tag = data[12:28]
    cipher = data[28:]
    return nonce, tag, cipher

def interact(client_socket, encryption_key, mac_key):
    while True:
        selection = int(input('\nMain Menu\n 1: Deposit\n 2: Withdrawal\n 3: Account Inquiry\n 4: Exit\nPlease enter selection: '))
        if selection == 1:
            deposit(client_socket, encryption_key, mac_key)
        elif selection == 2:
            withdrawal(client_socket, encryption_key, mac_key)
        elif selection == 3:
            account_inquiry(client_socket, encryption_key, mac_key)
        elif selection == 4:
            break
        else:
            print('Error: Please enter 1, 2, or 3.')

def deposit(client_socket, encryption_key, mac_key):
    amount = int(input('Please enter deposit amount: '))
    deposit = f'DEPOSIT:{amount}'
    nonce, tag, cipher = encrypt_AES(deposit, encryption_key)
    data = nonce + tag + cipher
    hmac_value = hmac.new(mac_key, data, hashlib.sha256).digest()
    client_socket.send(data + hmac_value)
    print(f'Deposit sent.')

def withdrawal(client_socket, encryption_key, mac_key):
    amount = int(input('Please enter withdrawal amount: '))
    withdrawal = f'WITHDRAWAL:{amount}'
    nonce, tag, cipher = encrypt_AES(withdrawal, encryption_key)
    data = nonce + tag + cipher
    hmac_value = hmac.new(mac_key, data, hashlib.sha256).digest()
    client_socket.send(data + hmac_value)
    print(f'Withdrawal sent.')

def account_inquiry(client_socket, encryption_key, mac_key):
    inquiry = f'INQUIRY:0'
    nonce, tag, cipher = encrypt_AES(inquiry, encryption_key)
    data = nonce + tag + cipher
    hmac_value = hmac.new(mac_key, data, hashlib.sha256).digest()
    client_socket.send(data + hmac_value)
    print(f'Inquiry sent.')
    received_data = b''
    while True:
        try:
            chunk = client_socket.recv(1024)
            if not chunk:
                print('Connection closed unexpectedly.')
                break
            if b'END_OF_TRANSACTIONS' in chunk:
                received_data += chunk
                break
            received_data += chunk
        except Exception as e:
            print(f'Error during receiving transactions: {e}')
    transactions = received_data.split(b'||')[:-1]
    print('\nAccount Transactions')
    for transaction in transactions:
        nonce = transaction[:12]
        tag = transaction[12:28]
        cipher = transaction[28:-32]
        received_hmac = transaction[-32:]
        if not verify_hmac(received_hmac, nonce + tag + cipher, mac_key):
            print('Error: MAC verification failed!')
            continue
        request = decrypt_AES(nonce, tag, cipher, string=True, decryption_key=encryption_key)
        print(f' {request}')

def main():

    host = '127.0.0.1'
    port = 8080
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client_socket.connect((host, port))
        print(f'\nConnected to server, {host}, at port, {port}\n')
        
        authenticate_bank(client_socket)
        
        # (2) Receive secret master key
        data = client_socket.recv(1024)
        nonce, tag, cipher = extract_data(data)
        master_secret_key = decrypt_AES(nonce, tag, cipher, False)
        print(f'Received master secret key, {master_secret_key.hex()}')

        # (3) Derive encryption key and MAC from master secret key
        encryption_key, mac_key = derive_keys(master_secret_key)
        print(f'Derived key-set\nEncryption_key, {encryption_key.hex()} \nMac_key, {mac_key.hex()}')

        # (4) Deposits, withdrawals, and balance inquiries
        interact(client_socket, encryption_key, mac_key)

    except Exception as e:
        print(f'Error in communcations with host: {e}')

    finally:
        client_socket.close()

if __name__ == '__main__':
    main()