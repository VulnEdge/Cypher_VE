# 🔐 CypherX – Hackers Choice
> AES-256 based file and text encryption tool | Developed by **VulnEdge**

![CypherX Banner](https://img.shields.io/badge/Encryption-AES--256-blue?style=flat-square)
![CypherX Python](https://img.shields.io/badge/Made%20with-Python3-green?style=flat-square)
![License MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)

CypherX is a powerful, user-friendly command-line tool designed for secure encryption and decryption of **files** and **text** using industry-standard **AES-256 (CBC mode)** encryption.

---

## 📦 Features

- 🔐 **AES-256 Encryption/Decryption**
- 📁 **Encrypt and Decrypt Files**
- 📝 **Encrypt and Decrypt Text**
- 🧂 Random salt and IV generation for each encryption
- 🧪 PBKDF2 key derivation with 100,000 iterations
- 🧼 Proper padding using PKCS7
- ❌ Password mismatch detection
- 🛡️ Base64 encoding for secure text handling
- ✅ Works on Linux, macOS, and Windows

---

## 📸 Preview

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

[+] Choose an option:
1. Encrypt File
2. Decrypt File
3. Encrypt Text
4. Decrypt Text
5. Exit

---

## 🚀 Installation

Make sure you have **Python 3.6+** and **pip** installed.

### Clone the Repository
git clone https://github.com/yourusername/CypherX.git
cd CypherX

### Install Required Packages
pip install cryptography

---

## 🛠️ Usage

Run the tool:
python3 cypherx.py

### Options:
- Encrypt File: Encrypts any file and saves it with `.enc` extension.
- Decrypt File: Decrypts a `.enc` file back to its original content.
- Encrypt Text: Encrypts user-input text, prints base64 output, optionally saves to file.
- Decrypt Text: Decrypts base64 input string using password.

---

## 🔒 Security Notes

- Uses **AES-256-CBC** encryption with a **random IV** and **PBKDF2HMAC** with SHA-256 for key derivation.
- Salt is generated randomly for each encryption to ensure strong cryptographic hygiene.
- Encrypted output includes: `[salt][iv][ciphertext]`, all base64 encoded.
- Ensure your password is strong and kept secure.

---

## 📁 Example

**Encrypting a File:**
[+] Enter file path to encrypt: secret.txt
[+] Enter password: ********
[+] Confirm password: ********
[+] File saved as: secret.txt.enc

**Decrypting Text:**
[+] Paste encrypted text (Base64): <paste here>
[+] Enter password: ********
[+] Decrypted Text: Hello, world!

---

## 📄 License

**CypherX** is licensed under the MIT License.

---

## 👨‍💻 Developed By

**VulnEdge**  
Security Enthusiasts | Cyber Researchers  
🔗 Follow us on GitHub: https://github.com/yourusername

---

✨ “Stay safe, encrypt everything.” – VulnEdge
