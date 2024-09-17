from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os



def generate():
    salt = os.urandom(16)
    key = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    keybytes = key.derive(b"password")  
    writeFile("key.txt", keybytes)
    return keybytes



def writeFile(filename, key):
    try:
        with open(filename, "w") as file:
            file.write(key.hex())  
    except Exception as e:
        print("Error")



def getInput():
    key = input("Enter the key: ")
    return bytes.fromhex(key)  



def getPlaintext():
    plaintext = input("Enter the plaintext: ")
    return plaintext.encode()  



def decrypt(key, iv, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(decrypted_padded_plaintext) + unpadder.finalize()
    return plaintext



def encrypt(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return (iv, ciphertext)



def main():
    key = generate()
    userInput = getInput()
    print("Input Key:", userInput.hex())
    if userInput == key:  
        print("Key matched. Enter message to do encryption or decryption.")
        plaintext = getPlaintext()
        iv, ciphertext = encrypt(key, plaintext)
        print("Encrypted ciphertext:", ciphertext.hex())
        decrypted = decrypt(key, iv, ciphertext)
        print("Decrypted plaintext:", decrypted.decode())
    else:
        print("Key did not match.")



if __name__ == "__main__":
    main()
