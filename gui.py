# gui.py

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
	root.geometry("700x650")

	default_font = ("Courier New", 11)
	label_font = ("Helvetica", 12, "bold")
	button_font = ("Helvetica", 12, "bold")
	button_config = {
		"font": button_font,
		"bg": "#e0e0e0",
		"fg": "#000000",
		"activebackground": "#c0c0c0",
		"activeforeground": "#000000",
		"padx": 10,
		"pady": 5
	}
	option_menu_config = {
		"font": button_font,
		"bg": "#f0f0f0",
		"fg": "#000000",
		"highlightthickness": 1,
		"width": 20
	}

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

	# Cipher Selection
	tk.Label(root, text="Select Cipher:", font=label_font).pack(pady=(10, 0))
	option_menu = tk.OptionMenu(root, cipher_var, *CIPHERS.keys(), command=update_cipher)
	option_menu.config(**option_menu_config)
	option_menu.pack()

	# Key Input
	tk.Label(root, text="Enter Key:", font=label_font).pack(pady=(10, 0))
	key_entry = tk.Entry(root, font=default_font)
	key_entry.pack()

	# Load File Button
	tk.Button(root, text="Load File", command=load_file, **button_config).pack(pady=5)

	# Message Input
	tk.Label(root, text="Message Input:", font=label_font).pack(pady=(10, 0))
	text_input = tk.Text(root, height=10, width=80, font=default_font)
	text_input.pack(pady=5)

	# Encrypt / Decrypt / Save Buttons
	tk.Button(root, text="Encrypt", command=encrypt, **button_config).pack(pady=5)
	tk.Button(root, text="Decrypt", command=decrypt, **button_config).pack(pady=5)
	tk.Button(root, text="Save Output", command=save_output, **button_config).pack(pady=5)

	# Output Text Box
	tk.Label(root, text="Output:", font=label_font).pack(pady=(10, 0))
	text_output = tk.Text(root, height=10, width=80, font=default_font)
	text_output.pack(pady=5)

	root.mainloop()

