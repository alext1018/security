import tkinter as tk

class Application(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        self.pack()
        self.create_widgets()

    def create_widgets(self):
        self.key_label = tk.Label(self, text="Enter the key:")
        self.key_label.pack()
        self.key_entry = tk.Entry(self)
        self.key_entry.pack()

        self.plaintext_label = tk.Label(self, text="Enter the plaintext:")
        self.plaintext_label.pack()
        self.plaintext_entry = tk.Entry(self)
        self.plaintext_entry.pack()

        self.encrypt_button = tk.Button(self, text="Encrypt", command=self.encrypt)
        self.encrypt_button.pack()

        self.decrypt_button = tk.Button(self, text="Decrypt", command=self.decrypt)
        self.decrypt_button.pack()

        self.output_label = tk.Label(self)
        self.output_label.pack()

    def encrypt(self):
        key = bytes.fromhex(self.key_entry.get())
        plaintext = self.plaintext_entry.get().encode()

        iv, ciphertext = encrypt_message(key, plaintext)
        self.output_label.config(text=f"Encrypted ciphertext: {ciphertext.hex()}")

    def decrypt(self):
        key = bytes.fromhex(self.key_entry.get())
        ciphertext = bytes.fromhex(self.output_label.cget("text").split(":")[1].strip())

        decrypted_plaintext = decrypt_message(key, ciphertext[:16], ciphertext[16:])
        self.output_label.config(text=f"Decrypted plaintext: {decrypted_plaintext.decode()}")

root = tk.Tk()
app = Application(master=root)
app.mainloop()
