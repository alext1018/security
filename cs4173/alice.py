import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hmac
import os

def generate_key():
    # Generate a random key
    key = os.urandom(16)
    write_key_to_file("key.txt", key)
    return key

def write_key_to_file(filename, key):
    try:
        with open(filename, "wb") as file:
            file.write(key)  # Write key as bytes
        print(f"Key written to file '{filename}'.")
    except Exception as e:
        print(f"Error writing key to file: {e}")

def encrypt_message(key, plaintext):
    # Generate a random initialization vector (IV)
    iv = os.urandom(16)
    # Create a Cipher object using AES in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    # Pad the plaintext to a multiple of 16 bytes
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()
    # Encrypt the padded plaintext
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Generate HMAC for ciphertext
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(ciphertext)
    tag = h.finalize()

    return (iv, ciphertext, tag)

def decrypt_message(key, iv, ciphertext, tag):
    # Verify HMAC
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(ciphertext)
    h.verify(tag)

    # Create a Cipher object using AES in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    # Decrypt the ciphertext
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    # Unpad the plaintext
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext

def generate_key_pressed():
    generated_key = generate_key()
    messagebox.showinfo("Generated Key", f"The generated key is: {generated_key.hex()}")

def encrypt_decrypt_pressed():
    user_key_hex = user_key_entry.get()
    user_key = bytes.fromhex(user_key_hex)
    plaintext = plaintext_entry.get().encode()

    if len(user_key) != 16:
        messagebox.showerror("Error", "Key must be 16 bytes (128 bits) long.")
        return

    try:
        if encrypt_decrypt_var.get() == 1:  # Encrypt
            iv, ciphertext, tag = encrypt_message(user_key, plaintext)
            ciphertext_entry.delete(0, tk.END)
            ciphertext_entry.insert(0, ciphertext.hex())
            messagebox.showinfo("Encryption", "Encryption successful.")
        else:  # Decrypt
            ciphertext_hex = ciphertext_entry.get()
            ciphertext = bytes.fromhex(ciphertext_hex)
            iv = iv_entry.get().encode()
            tag_hex = tag_entry.get()
            tag = bytes.fromhex(tag_hex)
            decrypted_plaintext = decrypt_message(user_key, iv, ciphertext, tag)
            decrypted_plaintext_entry.delete(0, tk.END)
            decrypted_plaintext_entry.insert(0, decrypted_plaintext.decode())
            messagebox.showinfo("Decryption", "Decryption successful.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")

# Create main window
window = tk.Tk()
window.title("Encryption and Decryption")

# Key generation frame
key_generation_frame = tk.Frame(window)
key_generation_frame.pack(padx=10, pady=10)

generate_key_button = tk.Button(key_generation_frame, text="Generate Key", command=generate_key_pressed)
generate_key_button.pack(side=tk.LEFT)

# Encryption/Decryption frame
encryption_decryption_frame = tk.Frame(window)
encryption_decryption_frame.pack(padx=10, pady=10)

user_key_label = tk.Label(encryption_decryption_frame, text="User Key (Hex):")
user_key_label.grid(row=0, column=0, sticky="w")
user_key_entry = tk.Entry(encryption_decryption_frame)
user_key_entry.grid(row=0, column=1, padx=5, pady=5)

plaintext_label = tk.Label(encryption_decryption_frame, text="Plaintext:")
plaintext_label.grid(row=1, column=0, sticky="w")
plaintext_entry = tk.Entry(encryption_decryption_frame)
plaintext_entry.grid(row=1, column=1, padx=5, pady=5)

ciphertext_label = tk.Label(encryption_decryption_frame, text="Ciphertext (Hex):")
ciphertext_label.grid(row=2, column=0, sticky="w")
ciphertext_entry = tk.Entry(encryption_decryption_frame)
ciphertext_entry.grid(row=2, column=1, padx=5, pady=5)

iv_label = tk.Label(encryption_decryption_frame, text="IV:")
iv_label.grid(row=3, column=0, sticky="w")
iv_entry = tk.Entry(encryption_decryption_frame)
iv_entry.grid(row=3, column=1, padx=5, pady=5)

tag_label = tk.Label(encryption_decryption_frame, text="Tag (Hex):")
tag_label.grid(row=4, column=0, sticky="w")
tag_entry = tk.Entry(encryption_decryption_frame)
tag_entry.grid(row=4, column=1, padx=5, pady=5)

encrypt_decrypt_var = tk.IntVar()
encrypt_decrypt_var.set(1)  # Set default value to encrypt

encrypt_radio_button = tk.Radiobutton(encryption_decryption_frame, text="Encrypt", variable=encrypt_decrypt_var, value=1)
encrypt_radio_button.grid(row=5, column=0, padx=5, pady=5)
decrypt_radio_button = tk.Radiobutton(encryption_decryption_frame, text="Decrypt", variable=encrypt_decrypt_var, value=0)
decrypt_radio_button.grid(row=5, column=1, padx=5, pady=5)

encrypt_decrypt_button = tk.Button(encryption_decryption_frame, text="Encrypt/")
