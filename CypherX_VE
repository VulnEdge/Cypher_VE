import base64
import os
import getpass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend

backend = default_backend()

# --- Utility Functions ---

def generate_key(password: str, salt: bytes = None) -> tuple:
    if not salt:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key = kdf.derive(password.encode())
    return key, salt

def encrypt_data(data: bytes, password: str) -> bytes:
    key, salt = generate_key(password)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(salt + iv + ciphertext)

def decrypt_data(ciphertext: bytes, password: str) -> bytes:
    data = base64.b64decode(ciphertext)
    salt = data[:16]
    iv = data[16:32]
    actual_ciphertext = data[32:]

    key, _ = generate_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()

    padded_data = decryptor.update(actual_ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()

# --- File Operations ---

def encrypt_file(file_path: str, password: str):
    with open(file_path, 'rb') as f:
        data = f.read()
    encrypted_data = encrypt_data(data, password)
    output_path = file_path + ".enc"
    with open(output_path, 'wb') as f:
        f.write(encrypted_data)
    print(f"[+] File saved as: {output_path}")

def decrypt_file(file_path: str, password: str):
    with open(file_path, 'rb') as f:
        data = f.read()
    try:
        decrypted_data = decrypt_data(data, password)
        output_path = file_path.replace(".enc", "")
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)
        print(f"[+] Decrypted file saved as: {output_path}")
    except Exception as e:
        print("[-] Decryption failed. Incorrect password or corrupted file.")

# --- Text Operations ---

def encrypt_text():
    text = input("[+] Enter text to encrypt: ").encode()
    password = getpass.getpass("[+] Enter password: ")
    confirm_pass = getpass.getpass("[+] Confirm password: ")
    if password != confirm_pass:
        print("[-] Passwords do not match.")
        return
    encrypted = encrypt_data(text, password)
    print(f"\n[+] Encrypted Text (Base64): \n{encrypted.decode()}")
    save = input("[?] Save to file? (y/n): ").strip().lower()
    if save == 'y':
        filename = input("[+] Enter filename: ") + ".enc"
        with open(filename, 'wb') as f:
            f.write(encrypted)
        print(f"[+] Saved as {filename}")

def decrypt_text():
    enc_text = input("[+] Paste encrypted text (Base64): ").strip()
    password = getpass.getpass("[+] Enter password: ")
    try:
        decrypted = decrypt_data(enc_text.encode(), password)
        print(f"\n[+] Decrypted Text: {decrypted.decode()}")
    except Exception as e:
        print("[-] Decryption failed. Wrong password or invalid data.")

# --- Main Menu ---

def show_banner():
    print(r"""
  _______       _______               _   
 |__   __|     |__   __|             | |  
    | |  _ __     | | ___  _ __   ___| |_ 
    | | | '_ \    | |/ _ \| '_ \ / _ \ __|
   _| |_| | | |   | | (_) | |_) |  __/ |_ 
  |_____|_| |_|   |_|\___/| .__/ \___|\__|
                          | |              
                          |_|             

        [+] CypherX – Hackers Choice [+]
          Developed by VulnEdge
""")

def main():
    show_banner()
    while True:
        print("\n[+] Choose an option:")
        print("1. Encrypt File")
        print("2. Decrypt File")
        print("3. Encrypt Text")
        print("4. Decrypt Text")
        print("5. Exit")
        choice = input("[+] Enter your choice (1-5): ")

        if choice == "1":
            path = input("[+] Enter file path to encrypt: ")
            if os.path.exists(path):
                password = getpass.getpass("[+] Enter password: ")
                confirm_pass = getpass.getpass("[+] Confirm password: ")
                if password == confirm_pass:
                    encrypt_file(path, password)
                else:
                    print("[-] Passwords do not match.")
            else:
                print("[-] File does not exist.")

        elif choice == "2":
            path = input("[+] Enter .enc file path to decrypt: ")
            if os.path.exists(path):
                password = getpass.getpass("[+] Enter password: ")
                decrypt_file(path, password)
            else:
                print("[-] File does not exist.")

        elif choice == "3":
            encrypt_text()

        elif choice == "4":
            decrypt_text()

        elif choice == "5":
            print("[+] Exiting... Stay secure!")
            break

        else:
            print("[-] Invalid choice. Please select between 1 and 5.")

if __name__ == "__main__":
    main()
