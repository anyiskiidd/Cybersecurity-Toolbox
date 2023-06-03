import os
import hashlib
from cryptography.fernet import Fernet
from Crypto.Cipher import AES, Blowfish, DES, ARC4, ChaCha20
from Crypto.Util.Padding import pad, unpad
from colorama import init, Fore
import requests
import getpass
import string
import random
import secrets
import pyperclip
import socket
import nmap
import rarfile

init(autoreset=True)

CREATOR = "https://github.com/anyiskiidd"
KEY_FILE = "encryption_key.key"

def calculate_hash(file_path):
    with open(file_path, 'rb') as file:
        content = file.read()
        hash_value = hashlib.sha256(content).hexdigest()
    return hash_value

def generate_aes_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as key_file:
        key_file.write(key)
    return key

def load_aes_key():
    if not os.path.exists(KEY_FILE):
        return generate_aes_key()
    with open(KEY_FILE, 'rb') as key_file:
        return key_file.read()

def scan_files():
    print(Fore.YELLOW + "Scanning files...")
    directory = input("Enter the directory path to scan: ")

    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            hash_value = calculate_hash(file_path)
            print(f"File: {file_path}  |  Hash: {hash_value}")

def encrypt_file_aes():
    print(Fore.YELLOW + "Encrypting file using AES...")
    file_path = input("Enter the full path of the file to encrypt: ")
    key = load_aes_key()

    cipher = AES.new(key, AES.MODE_CBC)
    encrypted_file_path = f"{file_path}.encrypted"
    
    with open(file_path, 'rb') as file:
        content = file.read()
        encrypted_content = cipher.encrypt(pad(content, AES.block_size))

    with open(encrypted_file_path, 'wb') as encrypted_file:
        encrypted_file.write(cipher.iv + encrypted_content)

    print("The file has been encrypted successfully.")

def decrypt_file_aes():
    print(Fore.YELLOW + "Decrypting file using AES...")
    file_path = input("Enter the full path of the file to decrypt: ")
    key = load_aes_key()

    with open(file_path, 'rb') as encrypted_file:
        iv = encrypted_file.read(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_content = encrypted_file.read()

    decrypted_content = unpad(cipher.decrypt(encrypted_content), AES.block_size)

    decrypted_file_path = file_path[:-10]  # Remove ".encrypted" from the file name
    with open(decrypted_file_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_content)

    print("The file has been decrypted successfully.")

def encrypt_file_blowfish():
    print(Fore.YELLOW + "Encrypting file using Blowfish...")
    file_path = input("Enter the full path of the file to encrypt: ")
    key = Fernet.generate_key()
    cipher = Blowfish.new(key, Blowfish.MODE_CBC)
    encrypted_file_path = f"{file_path}.encrypted"

    with open(file_path, 'rb') as file:
        content = file.read()
        encrypted_content = cipher.encrypt(pad(content, Blowfish.block_size))

    with open(encrypted_file_path, 'wb') as encrypted_file:
        encrypted_file.write(cipher.iv + encrypted_content)

    print("The file has been encrypted successfully.")
    print("Keep the encryption key secure.")

def decrypt_file_blowfish():
    print(Fore.YELLOW + "Decrypting file using Blowfish...")
    file_path = input("Enter the full path of the file to decrypt: ")
    key = getpass.getpass("Enter the decryption key: ")
    cipher = Blowfish.new(key, Blowfish.MODE_CBC)

    with open(file_path, 'rb') as encrypted_file:
        iv = encrypted_file.read(Blowfish.block_size)
        encrypted_content = encrypted_file.read()

    decrypted_content = unpad(cipher.decrypt(encrypted_content), Blowfish.block_size)

    decrypted_file_path = file_path[:-10]  # Remove ".encrypted" from the file name
    with open(decrypted_file_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_content)

    print("The file has been decrypted successfully.")

def encrypt_file_des():
    print(Fore.YELLOW + "Encrypting file using DES...")
    file_path = input("Enter the full path of the file to encrypt: ")
    key = Fernet.generate_key()[:8]
    cipher = DES.new(key, DES.MODE_CBC)
    encrypted_file_path = f"{file_path}.encrypted"

    with open(file_path, 'rb') as file:
        content = file.read()
        encrypted_content = cipher.encrypt(pad(content, DES.block_size))

    with open(encrypted_file_path, 'wb') as encrypted_file:
        encrypted_file.write(cipher.iv + encrypted_content)

    print("The file has been encrypted successfully.")
    print("Keep the encryption key secure.")

def decrypt_file_des():
    print(Fore.YELLOW + "Decrypting file using DES...")
    file_path = input("Enter the full path of the file to decrypt: ")
    key = getpass.getpass("Enter the decryption key: ")[:8]
    cipher = DES.new(key, DES.MODE_CBC)

    with open(file_path, 'rb') as encrypted_file:
        iv = encrypted_file.read(DES.block_size)
        encrypted_content = encrypted_file.read()

    decrypted_content = unpad(cipher.decrypt(encrypted_content), DES.block_size)

    decrypted_file_path = file_path[:-10]  # Remove ".encrypted" from the file name
    with open(decrypted_file_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_content)

    print("The file has been decrypted successfully.")

def encrypt_file_arc4():
    print(Fore.YELLOW + "Encrypting file using ARC4...")
    file_path = input("Enter the full path of the file to encrypt: ")
    key = Fernet.generate_key()
    cipher = ARC4.new(key)
    encrypted_file_path = f"{file_path}.encrypted"

    with open(file_path, 'rb') as file:
        content = file.read()
        encrypted_content = cipher.encrypt(content)

    with open(encrypted_file_path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted_content)

    print("The file has been encrypted successfully.")
    print("Keep the encryption key secure.")

def decrypt_file_arc4():
    print(Fore.YELLOW + "Decrypting file using ARC4...")
    file_path = input("Enter the full path of the file to decrypt: ")
    key = getpass.getpass("Enter the decryption key: ")
    cipher = ARC4.new(key)

    with open(file_path, 'rb') as encrypted_file:
        encrypted_content = encrypted_file.read()

    decrypted_content = cipher.decrypt(encrypted_content)

    decrypted_file_path = file_path[:-10]  # Remove ".encrypted" from the file name
    with open(decrypted_file_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_content)

    print("The file has been decrypted successfully.")

def encrypt_file_chacha20():
    print(Fore.YELLOW + "Encrypting file using ChaCha20...")
    file_path = input("Enter the full path of the file to encrypt: ")
    key = Fernet.generate_key()
    cipher = ChaCha20.new(key=key)
    encrypted_file_path = f"{file_path}.encrypted"

    with open(file_path, 'rb') as file:
        content = file.read()
        encrypted_content = cipher.encrypt(content)

    with open(encrypted_file_path, 'wb') as encrypted_file:
        encrypted_file.write(cipher.nonce + encrypted_content)

    print("The file has been encrypted successfully.")
    print("Keep the encryption key secure.")

def decrypt_file_chacha20():
    print(Fore.YELLOW + "Decrypting file using ChaCha20...")
    file_path = input("Enter the full path of the file to decrypt: ")
    key = getpass.getpass("Enter the decryption key: ")
    nonce_size = ChaCha20.NONCE_SIZE
    cipher = ChaCha20.new(key=key)

    with open(file_path, 'rb') as encrypted_file:
        nonce = encrypted_file.read(nonce_size)
        encrypted_content = encrypted_file.read()

    decrypted_content = cipher.decrypt(encrypted_content)

    decrypted_file_path = file_path[:-10]  # Remove ".encrypted" from the file name
    with open(decrypted_file_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_content)

    print("The file has been decrypted successfully.")

def encrypt_text_fernet():
    print(Fore.YELLOW + "Encrypting text using Fernet...")
    text = input("Enter the text to encrypt: ")
    key = Fernet.generate_key()
    cipher = Fernet(key)

    encrypted_text = cipher.encrypt(text.encode())

    print("Encrypted text:", encrypted_text.decode())
    print("Keep the encryption key secure.")

def analyze_website():
    print(Fore.YELLOW + "Website Analysis")
    url = input("Enter the URL of the website to analyze: ")

    try:
        print("Analyzing website...")

        response = requests.get(url)
        headers = response.headers
        content_type = headers.get("Content-Type")
        server = headers.get("Server")
        x_powered_by = headers.get("X-Powered-By")

        print(f"\n--- {Fore.CYAN}Website Analysis{Fore.RESET} ---")
        print(f"URL: {url}")
        print(f"Status Code: {response.status_code}")
        print(f"Content Type: {content_type}")
        print(f"Server: {server}")
        print(f"X-Powered-By: {x_powered_by}")

        print(f"\n--- {Fore.CYAN}Headers{Fore.RESET} ---")
        for key, value in headers.items():
            print(f"{key}: {value}")

        print("\n---", Fore.CYAN + "Port Scan" + Fore.RESET, "---")
        nm = nmap.PortScanner()
        nm.scan(url, arguments='-p1-65535 -T4 -v')
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    state = nm[host][proto][port]['state']
                    print(f"Port {port}: {state}")

    except requests.exceptions.RequestException as e:
        print("Error analyzing the website:", str(e))

def generate_password(length=12):
    chars = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(chars) for _ in range(length))
    return password

def generate_secure_password():
    print(Fore.YELLOW + "Generating secure password...")
    length = int(input("Enter the length of the password: "))
    use_digits = input("Include digits? (Yes/No): ").lower().startswith('y')
    use_letters = input("Include letters? (Yes/No): ").lower().startswith('y')
    use_symbols = input("Include symbols? (Yes/No): ").lower().startswith('y')

    if not use_digits and not use_letters and not use_symbols:
        print(Fore.RED + "The password must include at least one character type.")
        return

    chars = ""
    if use_digits:
        chars += string.digits
    if use_letters:
        chars += string.ascii_letters
    if use_symbols:
        chars += string.punctuation

    password = ''.join(secrets.choice(chars) for _ in range(length))
    pyperclip.copy(password)  # Copy the password to the clipboard

    print(Fore.GREEN + "Secure password generated and copied to clipboard.")
    print(Fore.GREEN + "Password:", password)

def check_password_strength(password):
    score = 0

    # Check password length
    if len(password) >= 8:
        score += 1

    # Check for digits
    if any(char.isdigit() for char in password):
        score += 1

    # Check for uppercase letters
    if any(char.isupper() for char in password):
        score += 1

    # Check for lowercase letters
    if any(char.islower() for char in password):
        score += 1

    # Check for symbols
    if any(char in string.punctuation for char in password):
        score += 1

    # Evaluate password strength
    if score == 0:
        strength = "Weak"
    elif score <= 2:
        strength = "Medium"
    elif score <= 4:
        strength = "Strong"
    else:
        strength = "Very Strong"

    return strength

def password_strength_menu():
    print(Fore.YELLOW + "\n=== PASSWORD STRENGTH CHECK ===")
    password = getpass.getpass("Enter the password to check: ")

    strength = check_password_strength(password)
    print("Password strength:", strength)

def rar_brute_force():
    print(Fore.YELLOW + "RAR File Brute Force")
    file_path = input("Enter the full path of the RAR file: ")
    wordlist_path = input("Enter the full path of the wordlist file: ")

    if not os.path.exists(file_path):
        print(Fore.RED + "The RAR file does not exist.")
        return

    if not os.path.exists(wordlist_path):
        print(Fore.RED + "The wordlist file does not exist.")
        return

    with rarfile.RarFile(file_path) as rar:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as wordlist:
            for password in wordlist:
                password = password.strip()
                try:
                    rar.extractall(path='.', pwd=password.encode())
                    print(Fore.GREEN + "Password found:", password)
                    return
                except rarfile.BadRarFile:
                    continue

    print(Fore.RED + "Password not found in the wordlist.")

def main_menu():
    print(Fore.YELLOW + f"=== CYBERSECURITY MENU (Created by {CREATOR}) ===")
    print("1. Scan files")
    print("2. File encryption and decryption")
    print("3. Encrypt text")
    print("4. Analyze a website")
    print("5. Generate a secure password")
    print("6. Generate a custom secure password")
    print("7. Check password strength")
    print("8. RAR file brute force")
    print("9. Quit")

    choice = input("Choose an option: ")

    if choice == "1":
        scan_files()
    elif choice == "2":
        encryption_decryption_menu()
    elif choice == "3":
        encrypt_text_fernet()
    elif choice == "4":
        analyze_website()
    elif choice == "5":
        length = int(input("Enter the password length (default: 12): "))
        password = generate_password(length)
        print("Generated secure password:", password)
    elif choice == "6":
        generate_secure_password()
    elif choice == "7":
        password_strength_menu()
    elif choice == "8":
        rar_brute_force()
    elif choice == "9":
        return
    else:
        print(Fore.RED + "Invalid option. Please try again.")
    print()
    main_menu()

def encryption_decryption_menu():
    print(Fore.YELLOW + "\n=== FILE ENCRYPTION AND DECRYPTION MENU ===")
    print("1. Encrypt using AES")
    print("2. Decrypt using AES")
    print("3. Encrypt using Blowfish")
    print("4. Decrypt using Blowfish")
    print("5. Encrypt using DES")
    print("6. Decrypt using DES")
    print("7. Encrypt using ARC4")
    print("8. Decrypt using ARC4")
    print("9. Encrypt using ChaCha20")
    print("10. Decrypt using ChaCha20")
    print("11. Return")

    choice = input("Choose an option: ")

    if choice == "1":
        encrypt_file_aes()
    elif choice == "2":
        decrypt_file_aes()
    elif choice == "3":
        encrypt_file_blowfish()
    elif choice == "4":
        decrypt_file_blowfish()
    elif choice == "5":
        encrypt_file_des()
    elif choice == "6":
        decrypt_file_des()
    elif choice == "7":
        encrypt_file_arc4()
    elif choice == "8":
        decrypt_file_arc4()
    elif choice == "9":
        encrypt_file_chacha20()
    elif choice == "10":
        decrypt_file_chacha20()
    elif choice == "11":
        return
    else:
        print(Fore.RED + "Invalid option. Please try again.")
    print()
    encryption_decryption_menu()

if __name__ == "__main__":
    main_menu()
