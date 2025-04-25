import time
from vigenere import VigenereCipher
from triple_des import TripleDES, generate_random_key
from aes import AES
from rsa import RSA

ciphers = {
	"Vigenere": VigenereCipher(),
	"Triple DES": TripleDES(),
	"AES": AES(),
	"RSA": RSA()
}

lengths = [10, 100, 1000, 5000, 10000, 20000, 50000]
messages = ["A" * l for l in lengths]

vigenere_key = "MYSECRETKEY"
tdes_keys = [generate_random_key() for _ in range(3)]
aes_key = "thisisakey123456"
rsa_keys = {"e": 65537, "d": 2753, "n": 3233}

for name, cipher in ciphers.items():
	print(f"\n=== {name} Cipher ===")
	for msg in messages:
		try:
			if name == "Vigenere":
				start = time.time()
				enc = cipher.encrypt(msg, vigenere_key)
				if isinstance(enc, tuple): enc = enc[0]
				enc_time = time.time() - start

				start = time.time()
				dec = cipher.decrypt(enc, vigenere_key)
				if isinstance(dec, tuple): dec = dec[0]
				dec_time = time.time() - start

				match = dec == msg

			elif name == "Triple DES":
				enc, enc_time = cipher.encrypt(msg, *tdes_keys)
				dec, dec_time = cipher.decrypt(enc, *tdes_keys)

				match = dec == msg

			elif name == "AES":
				start = time.time()
				enc = cipher.encrypt(msg, aes_key)
				enc_time = time.time() - start

				start = time.time()
				try:
					dec = cipher.decrypt(enc, aes_key)
					match = dec == msg
				except UnicodeDecodeError:
					dec = "<decode error>"
					match = False
				dec_time = time.time() - start

			elif name == "RSA":
				key_enc = f"{rsa_keys['e']},{rsa_keys['n']}"
				key_dec = f"{rsa_keys['d']},{rsa_keys['n']}"

				start = time.time()
				enc = cipher.encrypt(msg, key_enc)
				enc_time = time.time() - start

				start = time.time()
				dec = cipher.decrypt(enc, key_dec)
				dec_time = time.time() - start

				match = dec == msg

			status = "good" if match else "bad"
			print(f"Len {len(msg):>6} | Encrypt: {enc_time:.5f}s | Decrypt: {dec_time:.5f}s | Match: {status}")

		except Exception as e:
			print(f"Len {len(msg):>6} | ERROR: {e}")

