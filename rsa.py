class RSA:
    def __init__(self):
        print("RSA initialized")

    def encrypt(self, plaintext, key_str):
        print("RSA encrypt called with:", plaintext, key_str)
        return f"[Encrypted: {plaintext}]"

    def decrypt(self, ciphertext, key_str):
        print("RSA decrypt called with:", ciphertext, key_str)
        return f"[Decrypted: {ciphertext}]"
