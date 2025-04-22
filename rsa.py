from math import gcd, isqrt

class RSA:
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
        
    def is_prime(self, n):
        if n <= 1:
            return False
        if n <= 3:
            return True
        if n % 2 == 0 or n % 3 == 0:
            return False
        for i in range(5, isqrt(n) + 1, 6):
            if n % i == 0 or n % (i + 2) == 0:
                return False
        return True

    def factor_n(self, n):
        for i in range(2, isqrt(n) + 1):
            if n % i == 0:
                j = n // i
                if self.is_prime(i) and self.is_prime(j):
                    return i, j
        return None

    def modinv(self, a, m):
        def egcd(a, b):
            if a == 0:
                return b, 0, 1
            g, y, x = egcd(b % a, a)
            return g, x - (b // a) * y, y

        g, x, _ = egcd(a, m)
        if g != 1:
            return None
        return x % m

    def validate_keys(self, key_str, mode='encrypt', public_e=None):
        MAX_SAFE_N = 10_000_000  

        try:
            if mode == 'encrypt':
                e, n = map(int, key_str.strip().split(','))
                if e <= 1 or n <= 1:
                    return False, "e and n must be greater than 1"
                if e >= n:
                    return False, "e must be smaller than n"
                if n > MAX_SAFE_N:
                    return False, f"n is too large to factor in real-time (max {MAX_SAFE_N})."

                factors = self.factor_n(n)
                if not factors:
                    return False, "n must be a product of two distinct primes"
                p, q = factors
                phi = (p - 1) * (q - 1)
                if gcd(e, phi) != 1:
                    return False, "e must be coprime with φ(n)"

            elif mode == 'decrypt':
                d, n = map(int, key_str.strip().split(','))
                if d <= 1 or n <= 1:
                    return False, "d and n must be greater than 1"
                if d >= n:
                    return False, "d must be smaller than n"
                if n > MAX_SAFE_N:
                    return False, f"n is too large to factor in real-time (max {MAX_SAFE_N})."

                factors = self.factor_n(n)
                if not factors:
                    return False, "n must be a product of two distinct primes"
                p, q = factors
                phi = (p - 1) * (q - 1)

                if public_e is None:
                    return True, "Warning: Cannot fully verify d without public exponent (e)."
                expected_d = self.modinv(public_e, phi)
                if expected_d is None:
                    return False, "Invalid e: no modular inverse exists"
                if expected_d != d:
                    return False, f"Invalid d: expected modular inverse of e is {expected_d}"

            else:
                return False, "Invalid mode specified"

            return True, "Keys are valid"

        except Exception as e:
            return False, f"Validation error: {e}"
