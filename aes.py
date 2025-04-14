class AES:
    def encrypt(self, plaintext, key):
        print("AES encrypt called with:", plaintext, key)
        return f"[Encrypted: {plaintext}]"

    def decrypt(self, ciphertext_hex, key):
        print("AES decrypt called with:", ciphertext_hex, key)
        return f"[Decrypted: {ciphertext_hex}]"
