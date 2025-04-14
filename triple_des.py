class TripleDES:
    def encrypt(self, plaintext, key):
        print("TripleDES encrypt called with:", plaintext, key)
        return f"[Encrypted: {plaintext}]"

    def decrypt(self, ciphertext_hex, key):
        print("TripleDES decrypt called with:", ciphertext_hex, key)
        return f"[Decrypted: {ciphertext_hex}]"
