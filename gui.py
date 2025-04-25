import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from vigenere import VigenereCipher
from triple_des import TripleDES
from aes import AES
from rsa import RSA
from file_utils import read_file, save_file
import random, string

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
		selected = cipher_var.get()
		if selected == "RSA":
			key_entry.pack_forget()
			rsa_frame.pack(pady=5)
		else:
			rsa_frame.pack_forget()
			key_entry.pack()

	def generate_key():
		selected = cipher_var.get()
		if selected == "Vigenere":
			key = ''.join(random.choices(string.ascii_uppercase, k=8))
			key_entry.delete(0, tk.END)
			key_entry.insert(0, key)
		elif selected == "AES":
			key = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
			key_entry.delete(0, tk.END)
			key_entry.insert(0, key)
		elif selected == "Triple DES":
			k1 = ''.join(random.choices('01', k=64))
			k2 = ''.join(random.choices('01', k=64))
			k3 = ''.join(random.choices('01', k=64))
			key_entry.delete(0, tk.END)
			key_entry.insert(0, f"{k1},{k2},{k3}")
		elif selected == "RSA":
			rsa = CIPHERS['RSA']
			pub, priv = None, None
			for _ in range(5):
				p = rsa.generate_prime()
				q = rsa.generate_prime()
				if p != q:
					n = p * q
					phi = (p - 1) * (q - 1)
					e = 65537
					if gcd(e, phi) == 1:
						d = rsa.modinv(e, phi)
						pub = (e, n)
						priv = (d, n)
						break
			if pub and priv:
				e, n = pub
				d, _ = priv
				entry_e.delete(0, tk.END)
				entry_e.insert(0, str(e))
				entry_d.delete(0, tk.END)
				entry_d.insert(0, str(d))
				entry_n.delete(0, tk.END)
				entry_n.insert(0, str(n))

	def encrypt():
		cipher = CIPHERS[cipher_var.get()]
		message = text_input.get("1.0", tk.END).strip()
		selected = cipher_var.get()

		if selected == "Vigenere" and not key_entry.get().isalpha():
			messagebox.showerror("Key Error", "Vigenere key must be alphabetic only.")
			return

		try:
			if selected == "RSA":
				e = int(entry_e.get())
				n = int(entry_n.get())
				key = f"{e},{n}"
				valid, msg = cipher.validate_keys(key, mode='encrypt')
				if not valid:
					messagebox.showerror("RSA Key Error", msg)
					return
				encrypted = cipher.encrypt(message, key)
			elif selected == "Triple DES":
				k1, k2, k3 = [k.strip() for k in key_entry.get().split(",")]
				encrypted = cipher.encrypt(message, k1, k2, k3)
			else:
				key = key_entry.get()
				encrypted = cipher.encrypt(message, key)
		except Exception as e:
			messagebox.showerror("Encryption Error", str(e))
			return

		text_output.delete("1.0", tk.END)
		text_output.insert(tk.END, encrypted)

	def decrypt():
		cipher = CIPHERS[cipher_var.get()]
		message = text_input.get("1.0", tk.END).strip()
		selected = cipher_var.get()

		try:
			if selected == "RSA":
				d = int(entry_d.get())
				n = int(entry_n.get())
				key = f"{d},{n}"
				valid, msg = cipher.validate_keys(key, mode='decrypt', public_e=int(entry_e.get()))
				if not valid:
					messagebox.showerror("RSA Key Error", msg)
					return
				decrypted = cipher.decrypt(message, key)
			elif selected == "Triple DES":
				k1, k2, k3 = [k.strip() for k in key_entry.get().split(",")]
				decrypted = cipher.decrypt(message, k1, k2, k3)
			else:
				key = key_entry.get()
				decrypted = cipher.decrypt(message, key)
		except Exception as e:
			messagebox.showerror("Decryption Error", str(e))
			return

		text_output.delete("1.0", tk.END)
		text_output.insert(tk.END, decrypted)

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

	tk.Label(root, text="Select Cipher:", font=label_font).pack(pady=(10, 0))
	option_menu = tk.OptionMenu(root, cipher_var, *CIPHERS.keys(), command=update_cipher)
	option_menu.config(**option_menu_config)
	option_menu.pack()

	tk.Button(root, text="Generate Key", command=generate_key, **button_config).pack(pady=5)
	tk.Label(root, text="Enter Key:", font=label_font).pack(pady=(10, 0))
	key_container = tk.Frame(root)
	key_container.pack()

	key_entry = tk.Entry(key_container, font=default_font, width=80)
	key_entry.pack()

	rsa_frame = tk.Frame(key_container)
	tk.Label(rsa_frame, text="Public Exponent (e):", font=label_font).grid(row=0, column=0, sticky="e")
	entry_e = tk.Entry(rsa_frame, font=default_font, width=10)
	entry_e.grid(row=0, column=1, padx=5)
	tk.Label(rsa_frame, text="Private Exponent (d):", font=label_font).grid(row=1, column=0, sticky="e")
	entry_d = tk.Entry(rsa_frame, font=default_font, width=10)
	entry_d.grid(row=1, column=1, padx=5)
	tk.Label(rsa_frame, text="Modulus (n):", font=label_font).grid(row=2, column=0, sticky="e")
	entry_n = tk.Entry(rsa_frame, font=default_font, width=10)
	entry_n.grid(row=2, column=1, padx=5)

	tk.Button(root, text="Load File", command=load_file, **button_config).pack(pady=5)
	tk.Label(root, text="Message Input:", font=label_font).pack(pady=(10, 0))
	text_input = tk.Text(root, height=10, width=80, font=default_font)
	text_input.pack(pady=5)
	tk.Button(root, text="Encrypt", command=encrypt, **button_config).pack(pady=5)
	tk.Button(root, text="Decrypt", command=decrypt, **button_config).pack(pady=5)
	tk.Button(root, text="Save Output", command=save_output, **button_config).pack(pady=5)
	tk.Label(root, text="Output:", font=label_font).pack(pady=(10, 0))
	text_output = tk.Text(root, height=10, width=80, font=default_font)
	text_output.pack(pady=5)

	update_cipher()
	root.mainloop()

