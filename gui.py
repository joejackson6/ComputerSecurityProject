import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from vigenere import VigenereCipher
from triple_des import TripleDES
from aes import AES
from rsa import RSA
from file_utils import read_file, save_file

CIPHERS = {
    "Vigenere": VigenereCipher(),
    "Triple DES": TripleDES(),
    "AES": AES(),
    "RSA": RSA()
}

def launch_gui():
    root = tk.Tk()
    root.title("Cryptography Visualization Tool")
    root.geometry("700x600")

	# 
    cipher_var = tk.StringVar(value="Vigenere")

    def update_cipher(*args):
        text_output.delete("1.0", tk.END)

    def encrypt():
        cipher = CIPHERS[cipher_var.get()]
        message = text_input.get("1.0", tk.END).strip()
        key = key_entry.get()
        try:
            encrypted = cipher.encrypt(message, key)
            text_output.delete("1.0", tk.END)
            text_output.insert(tk.END, encrypted)
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))

    def decrypt():
        cipher = CIPHERS[cipher_var.get()]
        message = text_input.get("1.0", tk.END).strip()
        key = key_entry.get()
        try:
            decrypted = cipher.decrypt(message, key)
            text_output.delete("1.0", tk.END)
            text_output.insert(tk.END, decrypted)
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))

    def load_file():
        path = filedialog.askopenfilename()
        if path:
            content = read_file(path)
            text_input.delete("1.0", tk.END)
            text_input.insert(tk.END, content)

    def save_output():
        content = text_output.get("1.0", tk.END).strip()
        path = filedialog.asksaveasfilename()
        if path:
            save_file(path, content)

    ttk.Label(root, text="Select Cipher:").pack()
    ttk.OptionMenu(root, cipher_var, *CIPHERS.keys(), command=update_cipher).pack()

    ttk.Label(root, text="Key:").pack()
    key_entry = ttk.Entry(root)
    key_entry.pack()

    ttk.Button(root, text="Load File", command=load_file).pack()
    text_input = tk.Text(root, height=10, width=80)
    text_input.pack()

    ttk.Button(root, text="Encrypt", command=encrypt).pack()
    ttk.Button(root, text="Decrypt", command=decrypt).pack()
    ttk.Button(root, text="Save Output", command=save_output).pack()

    text_output = tk.Text(root, height=10, width=80)
    text_output.pack()

    root.mainloop()


