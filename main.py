import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
import tkinter as tk

class AESCipher:
    def __init__(self, key):
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return AESCipher._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

def encrypt_text():
    key = key_entry.get()
    message = message_entry.get("1.0", tk.END)

    cipher = AESCipher(key)
    encrypted_message = cipher.encrypt(message)
    result_text.delete("1.0", tk.END)
    result_text.insert(tk.END, encrypted_message.decode())

def decrypt_text():
    key = key_entry.get()
    message = message_entry.get("1.0", tk.END)

    cipher = AESCipher(key)
    decrypted_message = cipher.decrypt(message)
    result_text.delete("1.0", tk.END)
    result_text.insert(tk.END, decrypted_message)

root = tk.Tk()
root.title("AES-256 Encryption/Decryption")

key_label = tk.Label(root, text="Enter encryption key:")
key_label.pack()

key_entry = tk.Entry(root, width=50)
key_entry.pack()

message_label = tk.Label(root, text="Enter message to encrypt/decrypt:")
message_label.pack()

message_entry = tk.Text(root, height=10, width=50)
message_entry.pack()

encrypt_button = tk.Button(root, text="Encrypt", command=encrypt_text)
encrypt_button.pack()

decrypt_button = tk.Button(root, text="Decrypt", command=decrypt_text)
decrypt_button.pack()

result_label = tk.Label(root, text="Result:")
result_label.pack()

result_text = tk.Text(root, height=10, width=50)
result_text.pack()

root.mainloop()
