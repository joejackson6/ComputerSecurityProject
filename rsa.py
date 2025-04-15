class RSA:
    def __init__(self):
        print("RSA initialized")

    def encrypt(self, plaintext, key_str):
        try:
            e, n = map(int, key_str.strip().split(','))
            cipher = [pow(ord(char), e, n) for char in plaintext]
            return ' '.join(map(str, cipher))  # Return as space-separated string
        except Exception as ex:
            return f"[RSA Encrypt Error] {ex}"

    def decrypt(self, ciphertext, key_str):
        try:
            d, n = map(int, key_str.strip().split(','))
            cipher_nums = list(map(int, ciphertext.strip().split()))
            plain = [chr(pow(char, d, n)) for char in cipher_nums]
            return ''.join(plain)
        except Exception as ex:
            return f"[RSA Decrypt Error] {ex}"
