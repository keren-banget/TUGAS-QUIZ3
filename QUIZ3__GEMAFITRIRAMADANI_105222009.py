def to_binary(text):
    return ''.join(format(ord(c), '08b') for c in text)

def from_binary(binary_str):
    chars = [chr(int(binary_str[i:i+8], 2)) for i in range(0, len(binary_str), 8)]
    return ''.join(chars)

def pad_binary(data, block_size=64):
    pad_len = block_size - (len(data) % block_size)
    return data + '0' * pad_len

def xor_blocks(block1, block2):
    return ''.join('0' if b1 == b2 else '1' for b1, b2 in zip(block1, block2))

def encrypt(plaintext, key):
    
    binary_plaintext = to_binary(plaintext)
    binary_key = to_binary(key[:8])  

  
    binary_plaintext = pad_binary(binary_plaintext, 64)
    binary_key = pad_binary(binary_key, 64)


    ciphertext_blocks = []
    for i in range(0, len(binary_plaintext), 64):
        block = binary_plaintext[i:i+64]
        cipher_block = xor_blocks(block, binary_key)
        ciphertext_blocks.append(cipher_block)


    ciphertext_binary = ''.join(ciphertext_blocks)
    return ciphertext_binary

def decrypt(ciphertext_binary, key):
    binary_key = to_binary(key[:8])
    binary_key = pad_binary(binary_key, 64)

    plaintext_blocks = []
    for i in range(0, len(ciphertext_binary), 64):
        block = ciphertext_binary[i:i+64]
        plain_block = xor_blocks(block, binary_key)
        plaintext_blocks.append(plain_block)

    decrypted_binary = ''.join(plaintext_blocks)
    return from_binary(decrypted_binary).rstrip('\x00')


plaintext = "KEKERASAN DI LINGKUNGAN PERTAMINA"
key = "UNIVERSITAS PERTAMINA"

cipher_binary = encrypt(plaintext, key)
print("Hasil Enkripsi (biner):", cipher_binary)

decrypted_text = decrypt(cipher_binary, key)
print("Hasil Dekripsi:", decrypted_text)
