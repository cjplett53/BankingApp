import os
from encryption_algorithms import decrypt_AES

# Define a long term logging key
logging_key = b'12345678901234567890123456789012'

def decrypt_with_key(hex_str, key, string=True, has_hmac=False):
    data = bytes.fromhex(hex_str)
    if has_hmac:
        data = data[:-32]  # Remove the appended HMAC (32 bytes)
    nonce = data[:12]
    tag = data[12:28]
    cipher = data[28:]
    return decrypt_AES(nonce, tag, cipher, string=string, decryption_key=key)

def decrypt_transaction_line(line):
    parts = line.strip().split("||")
    if len(parts) != 2:
        return "Invalid transaction data format"
    enc_wrapped_key, enc_composite = parts
    
    # Unwrap the session key using the logging_key
    session_key = decrypt_with_key(enc_wrapped_key, logging_key, string=False, has_hmac=False)
    if session_key is None:
        return "Failed to unwrap session key"
    
    # Decrypt the message using the session key
    composite = decrypt_with_key(enc_composite, session_key, string=True, has_hmac=True)
    if composite is None:
        return "Failed to decrypt composite message"
    
    subparts = composite.split("||")
    if len(subparts) != 3:
        return "Invalid data format"
    username, transaction, timestamp = subparts
    return f"{transaction} ({username}) at {timestamp}"

def main():
    if not os.path.exists("customer_transactions.txt"):
        print("No transactions file found.")
        return

    print("Decrypting transactions from customer_transactions.txt:\n")
    with open("customer_transactions.txt", "r") as f:
        lines = f.readlines()

    if not lines:
        print("No transactions stored")
        return

    for line in lines:
        decrypted = decrypt_transaction_line(line)
        print("Decrypted Transaction:", decrypted)

if __name__ == '__main__':
    main()