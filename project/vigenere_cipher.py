#!/usr/bin/env python3
# Vigenère Cipher Implementation 

class VigenereCipher:
    def __init__(self):
        self.name = "Vigenère Cipher"
    
    def char_to_int(self, char):
        """Convert a character to its corresponding integer value (A=0, B=1, etc.)."""
        return ord(char.upper()) - ord('A')
    
    def int_to_char(self, num):
        """Convert an integer to its corresponding character (0=A, 1=B, etc.)."""
        return chr(num % 26 + ord('A'))
    
    def prepare_text(self, text):
        """Remove non-alphabetic characters and convert to uppercase."""
        return ''.join(char for char in text.upper() if char.isalpha())
    
    def prepare_key(self, key, message_length):
        """Repeat the key to match the length of the message."""
        # remove non-alphabetic characters and convert to uppercase
        key = self.prepare_text(key)
        
        # if key is empty after preparation, return an error
        if not key:
            raise ValueError("Key must contain at least one letter")
        
        # repeat the key to match or exceed message length
        repeated_key = (key * (message_length // len(key) + 1))[:message_length]
        
        return repeated_key
    
    def encrypt(self, plaintext, key):
        """
        Encrypt plaintext using Vigenère cipher with the given key.
        
        Args:
            plaintext: The text to encrypt
            key: The encryption key
            
        Returns:
            Encrypted text and execution time
        """
        start_time = __import__('time').time()
        
        # prepare plaintext and key
        plaintext = self.prepare_text(plaintext)
        if not plaintext:
            return "", 0 
        
        key = self.prepare_key(key, len(plaintext))
        
        # encrypt each character
        ciphertext = ""
        for i in range(len(plaintext)):
            # convert plaintext and key characters to numbers
            p = self.char_to_int(plaintext[i])
            k = self.char_to_int(key[i])
            
            # apply Vigenère encryption formula: (p + k) mod 26
            encrypted_char = (p + k) % 26
            
            # convert back to character and append to result
            ciphertext += self.int_to_char(encrypted_char)
        
        end_time = __import__('time').time()
        execution_time = end_time - start_time
        
        return ciphertext, execution_time
    
    def decrypt(self, ciphertext, key):
        """
        Decrypt ciphertext using Vigenère cipher with the given key.
        
        Args:
            ciphertext: The text to decrypt
            key: The decryption key
            
        Returns:
            Decrypted text and execution time
        """
        start_time = __import__('time').time()
        
        # prepare ciphertext and key
        ciphertext = self.prepare_text(ciphertext)
        if not ciphertext:
            return "", 0
        
        key = self.prepare_key(key, len(ciphertext))
        
        # decrypt each character
        plaintext = ""
        for i in range(len(ciphertext)):
            # cnvert ciphertext and key characters to numbers
            c = self.char_to_int(ciphertext[i])
            k = self.char_to_int(key[i])
            
            # apply Vigenère decryption formula: (c - k) mod 26
            decrypted_char = (c - k) % 26
            
            # convert back to character and append to result
            plaintext += self.int_to_char(decrypted_char)
        
        end_time = __import__('time').time()
        execution_time = end_time - start_time
        
        return plaintext, execution_time
    
    def get_encryption_table(self, plaintext, key):
        """
        Generate a table showing the encryption process.
        
        Returns a dictionary with the encryption steps.
        """
        plaintext = self.prepare_text(plaintext)
        if not plaintext:
            return None
        
        key = self.prepare_key(key, len(plaintext))
        encrypted, _ = self.encrypt(plaintext, key)
        
        table = {
            'plaintext': list(plaintext),
            'key': list(key),
            'ciphertext': list(encrypted),
            'steps': []
        }
        
        for i in range(len(plaintext)):
            p = self.char_to_int(plaintext[i])
            k = self.char_to_int(key[i])
            c = (p + k) % 26
            
            table['steps'].append({
                'plaintext_char': plaintext[i],
                'plaintext_val': p,
                'key_char': key[i],
                'key_val': k,
                'ciphertext_char': encrypted[i],
                'ciphertext_val': c,
                'formula': f"({p} + {k}) mod 26 = {c}"
            })
        
        return table
    
    def get_decryption_table(self, ciphertext, key):
        """
        Generate a table showing the decryption process.
        
        Returns a dictionary with the decryption steps.
        """
        ciphertext = self.prepare_text(ciphertext)
        if not ciphertext:
            return None
        
        key = self.prepare_key(key, len(ciphertext))
        decrypted, _ = self.decrypt(ciphertext, key)
        
        table = {
            'ciphertext': list(ciphertext),
            'key': list(key),
            'plaintext': list(decrypted),
            'steps': []
        }
        
        for i in range(len(ciphertext)):
            c = self.char_to_int(ciphertext[i])
            k = self.char_to_int(key[i])
            p = (c - k) % 26
            
            table['steps'].append({
                'ciphertext_char': ciphertext[i],
                'ciphertext_val': c,
                'key_char': key[i],
                'key_val': k,
                'plaintext_char': decrypted[i],
                'plaintext_val': p,
                'formula': f"({c} - {k}) mod 26 = {p}"
            })
        
        return table 