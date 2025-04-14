#!/usr/bin/env python3
# Triple DES (3DES) Implementation 

# DES Tables/Constants
# Initial and Final Permutation Tables
ip = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

ip_inverse = [40, 8, 48, 16, 56, 24, 64, 32,
              39, 7, 47, 15, 55, 23, 63, 31,
              38, 6, 46, 14, 54, 22, 62, 30,
              37, 5, 45, 13, 53, 21, 61, 29,
              36, 4, 44, 12, 52, 20, 60, 28,
              35, 3, 43, 11, 51, 19, 59, 27,
              34, 2, 42, 10, 50, 18, 58, 26,
              33, 1, 41, 9, 49, 17, 57, 25]

# Expansion Table
expansion_table = [32, 1, 2, 3, 4, 5,
                   4, 5, 6, 7, 8, 9,
                   8, 9, 10, 11, 12, 13,
                   12, 13, 14, 15, 16, 17,
                   16, 17, 18, 19, 20, 21,
                   20, 21, 22, 23, 24, 25,
                   24, 25, 26, 27, 28, 29,
                   28, 29, 30, 31, 32, 1]

# Permutation for the f function
p_box = [16, 7, 20, 21, 29, 12, 28, 17,
         1, 15, 23, 26, 5, 18, 31, 10,
         2, 8, 24, 14, 32, 27, 3, 9,
         19, 13, 30, 6, 22, 11, 4, 25]

# S-Boxes
s_boxes = [
    # S1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    # S2
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    # S3
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    # S4
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    # S5
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    # S6
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    # S7
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    # S8
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]

# Key Generation Tables
pc1 = [57, 49, 41, 33, 25, 17, 9,
       1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27,
       19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15,
       7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29,
       21, 13, 5, 28, 20, 12, 4]

pc2 = [14, 17, 11, 24, 1, 5,
       3, 28, 15, 6, 21, 10,
       23, 19, 12, 4, 26, 8,
       16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55,
       30, 40, 51, 45, 33, 48,
       44, 49, 39, 56, 34, 53,
       46, 42, 50, 36, 29, 32]

# Left shifts for key schedule
key_shifts = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]


# DES Functions
def permute(input_block, permutation_table):
    """Apply a permutation table to the input block."""
    output = ""
    for pos in permutation_table:
        output += input_block[pos - 1]
    return output

def left_shift(key, shift_amount):
    """Perform a left circular shift on the key."""
    return key[shift_amount:] + key[:shift_amount]

def xor(a, b):
    """Perform XOR operation on two binary strings."""
    result = ""
    for i in range(len(a)):
        if a[i] == b[i]:
            result += "0"
        else:
            result += "1"
    return result

def apply_sbox(expanded_block):
    """Apply S-boxes to the expanded block."""
    output = ""
    for i in range(8):
        # extract 6-bit chunk
        chunk = expanded_block[i*6:(i+1)*6]
        
        # concatenate strings for row and parse column
        row_bits = chunk[0] + chunk[5]
        row = int(row_bits, 2)
        col = int(chunk[1:5], 2)
        
        # get val from S-box
        val = s_boxes[i][row][col]
        
        # convert to 4-bit binary and append
        binary = format(val, '04b')
        output += binary
    
    return output

def f_function(right_half, subkey):
    """The Feistel function used in DES."""
    # expand right half from 32 to 48 bits
    expanded = permute(right_half, expansion_table)
    
    # XOR with the subkey
    xor_result = xor(expanded, subkey)
    
    # apply S-boxes to get 32 bits
    s_box_output = apply_sbox(xor_result)
    
    # apply P-box permutation
    return permute(s_box_output, p_box)

def generate_subkeys(key):
    """Generate the 16 subkeys for DES."""
    # apply PC-1 permutation to the key
    key = permute(key, pc1)
    
    # split left and right halves
    left_half = key[:28]
    right_half = key[28:]
    
    subkeys = []
    
    for i in range(16):
        # apply shift for this round
        left_half = left_shift(left_half, key_shifts[i])
        right_half = left_shift(right_half, key_shifts[i])
        
        # combine halves and apply PC-2 permutation
        combined = left_half + right_half
        subkey = permute(combined, pc2)
        
        subkeys.append(subkey)
    
    return subkeys

def des_encrypt(plaintext, key):
    """Encrypt a message using DES algorithm."""
    # generate subkeys
    subkeys = generate_subkeys(key)
    
    # apply initial permutation
    plaintext = permute(plaintext, ip)
    
    # split into left and right halves
    left_half = plaintext[:32]
    right_half = plaintext[32:]
    
    # 16 rounds of encryption
    for i in range(16):
        # save curr right half
        old_right = right_half
        
        # apply f function
        f_result = f_function(right_half, subkeys[i])
        
        # the new right half is the old left half XORed with the f function result
        right_half = xor(left_half, f_result)
        
        # the new left half is the old right half
        left_half = old_right
    
    # swap the halves
    combined = right_half + left_half
    
    # apply final permutation
    ciphertext = permute(combined, ip_inverse)
    
    return ciphertext

def des_decrypt(ciphertext, key):
    """Decrypt a message using DES algorithm."""
    # generate subkeys
    subkeys = generate_subkeys(key)
    subkeys.reverse()  # reverse because decryption
    
    # apply initial permutation
    ciphertext = permute(ciphertext, ip)
    
    # split into left and right halves
    left_half = ciphertext[:32]
    right_half = ciphertext[32:]
    
    # 16 rounds of decryption
    for i in range(16):
        # save curr right half
        old_right = right_half
        
        # apply f function
        f_result = f_function(right_half, subkeys[i])
        
        # the new right half is the old left half XORed with the f function result
        right_half = xor(left_half, f_result)
        
        # the new left half is the old right half
        left_half = old_right
    
    # swap the halves
    combined = right_half + left_half
    
    # apply final permutation
    plaintext = permute(combined, ip_inverse)
    
    return plaintext

def binary_to_hex(binary):
    """Convert a binary string to hex."""
    hex_result = ""
    for i in range(0, len(binary), 4):
        chunk = binary[i:i+4]
        hex_val = format(int(chunk, 2), 'x')
        hex_result += hex_val
    return hex_result

def hex_to_binary(hex_string):
    """Convert a hex string to binary."""
    binary = ""
    for char in hex_string:
        binary += format(int(char, 16), '04b')
    return binary

def text_to_binary(text):
    """Convert text to binary string."""
    binary = ""
    for char in text:
        binary += format(ord(char), '08b')
    
    if len(binary) % 64 != 0:
        padding_needed = 64 - (len(binary) % 64)
        binary += '0' * padding_needed
    
    return binary

def binary_to_text(binary):
    """Convert binary to text, ignoring padding zeros at the end."""
    text = ""
    for i in range(0, len(binary), 8):
        byte = binary[i:i+8]
        if byte != "00000000":  
            text += chr(int(byte, 2))

    return text.rstrip('\x00')

def triple_des_encrypt(plaintext_block, key1, key2, key3):
    """
    Triple DES Encryption (EDE mode): Encrypt-Decrypt-Encrypt
    """
    # encrypt with key1
    temp1 = des_encrypt(plaintext_block, key1)
    
    # decrypt with key2
    temp2 = des_decrypt(temp1, key2)
    
    # encrypt with key3
    return des_encrypt(temp2, key3)

def triple_des_decrypt(ciphertext_block, key1, key2, key3):
    """
    Triple DES Decryption (EDE mode): Decrypt-Encrypt-Decrypt
    """
    # decrypt with key3
    temp1 = des_decrypt(ciphertext_block, key3)
    
    # encrypt with key2
    temp2 = des_encrypt(temp1, key2)
    
    # decrypt with key1
    return des_decrypt(temp2, key1)

class TripleDES:
    def __init__(self):
        self.name = "Triple DES"
    
    def encrypt(self, plaintext, key1, key2, key3):
        """
        Encrypt text using Triple DES.
        
        Args:
            plaintext: The text to encrypt
            key1, key2, key3: The three 64-bit keys in binary string format
        
        Returns:
            The encrypted text in hexadecimal format
        """
        start_time = __import__('time').time()
        
        binary = text_to_binary(plaintext)
        
        # process each 64-bit block
        encrypted_blocks = []
        for i in range(0, len(binary), 64):
            block = binary[i:i+64]
            encrypted_block = triple_des_encrypt(block, key1, key2, key3)
            encrypted_blocks.append(encrypted_block)
        
        # combine all encrypted blocks and convert to hex for display
        result_binary = ''.join(encrypted_blocks)
        result_hex = binary_to_hex(result_binary)
        
        end_time = __import__('time').time()
        execution_time = end_time - start_time
        
        return result_hex, execution_time
    
    def decrypt(self, ciphertext_hex, key1, key2, key3):
        """
        Decrypt hexadecimal ciphertext using Triple DES.
        
        Args:
            ciphertext_hex: The hexadecimal ciphertext
            key1, key2, key3: The three 64-bit keys in binary string format
        
        Returns:
            The decrypted text
        """
        start_time = __import__('time').time()
        
        binary = hex_to_binary(ciphertext_hex)
        
        # process each 64-bit block
        decrypted_blocks = []
        for i in range(0, len(binary), 64):
            block = binary[i:i+64]
            # ensure block is 64 bits (pad if necessary)
            if len(block) < 64:
                block = block.ljust(64, '0')
            decrypted_block = triple_des_decrypt(block, key1, key2, key3)
            decrypted_blocks.append(decrypted_block)
        
        # combine all decrypted blocks and convert to text
        result_binary = ''.join(decrypted_blocks)
        result_text = binary_to_text(result_binary)
        
        end_time = __import__('time').time()
        execution_time = end_time - start_time
        
        return result_text, execution_time

# utility functions
def generate_random_key():
    """Generate a random 64-bit key in binary format."""
    import random
    return ''.join(random.choice('01') for _ in range(64))

def validate_binary_key(key):
    """Validate that the key is 64 bits of binary."""
    if len(key) != 64:
        return False
    return all(bit in '01' for bit in key) 