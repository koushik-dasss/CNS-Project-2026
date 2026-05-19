from Cryptodome.Cipher import DES3
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
import base64

BLOCK_SIZE = DES3.block_size

def generate_random_key() -> bytes:
    while True:
        try:
            key = get_random_bytes(24)
            return DES3.adjust_key_parity(key)
        except ValueError:
            continue

def encrypt_message(message: str, key: bytes) -> str:
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    padded_message = pad(message.encode('utf-8'), BLOCK_SIZE)
    ciphertext = cipher.encrypt(padded_message)
    return base64.b64encode(iv + ciphertext).decode('utf-8')

def decrypt_message(ciphertext_b64: str, key: bytes) -> str:
    encrypted_data = base64.b64decode(ciphertext_b64)
    iv = encrypted_data[:BLOCK_SIZE]
    ciphertext = encrypted_data[BLOCK_SIZE:]
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, BLOCK_SIZE)
    return plaintext.decode('utf-8')

def test_wrong_key(key: bytes):
    print('\n[WRONG KEY TEST]')
    message = 'Confidential Banking Data'
    encrypted = encrypt_message(message, key)
    wrong_key = generate_random_key()
    try:
        decrypt_message(encrypted, wrong_key)
        print('Unexpected Success')
    except Exception:
        print('PASS — Wrong key decryption failed successfully.')

def test_iv_randomness(key: bytes):
    print('\n[IV RANDOMNESS TEST]')
    message = 'Same Message Every Time'
    encrypted_1 = encrypt_message(message, key)
    encrypted_2 = encrypt_message(message, key)
    encrypted_3 = encrypt_message(message, key)
    print(f'\nEncrypted Output 1 : {encrypted_1}')
    print(f'Encrypted Output 2 : {encrypted_2}')
    print(f'Encrypted Output 3 : {encrypted_3}')
    if len({encrypted_1, encrypted_2, encrypted_3}) == 3:
        print()
        print('PASS — Ciphertexts are different because of random IV.')
    else:
        print('\nFAIL — Ciphertexts should not be identical.')

def edge_case_testing(key: bytes):
    print('\n[EDGE CASE TESTING]')
    test_cases = [
        ('Single Character', 'A'),
        ('Exactly 8 Bytes', '12345678'),
        ('Special Characters', '!@#$%^&*()_+-=[]{}'),
        ('Unicode Characters', 'Hello नमस्ते 🔐'),
        ('Long Message', 'Security Matters ' * 100)
    ]
    print(f"\n{'Test Case':<25}{'Status':>15}")
    print('-' * 45)
    for title, message in test_cases:
        try:
            encrypted = encrypt_message(message, key)
            decrypted = decrypt_message(encrypted, key)
            result = 'PASS' if decrypted == message else 'FAIL'
        except Exception:
            result = 'ERROR'
        print(f'{title:<25}{result:>15}')

def main():
    print('=' * 60)
    print('         SECURITY TESTING OF TRIPLE DES')
    print('=' * 60)
    key = generate_random_key()
    print('\nSecure Random Key Generated Successfully.')
    test_wrong_key(key)
    test_iv_randomness(key)
    edge_case_testing(key)
    print('\n' + '=' * 60)

if __name__ == '__main__':
    main()
