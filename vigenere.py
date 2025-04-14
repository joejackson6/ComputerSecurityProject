class VigenereCipher:
    def encrypt(self, text, key):
        print("Vigenere encrypt called with:", text, key)
        return f"[Encrypted: {text}]"

    def decrypt(self, text, key):
        print("Vigenere decrypt called with:", text, key)
        return f"[Decrypted: {text}]"
