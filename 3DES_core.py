from Cryptodome.Cipher import DES3
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
import base64
import hashlib
import time
BLOCK_SIZE = DES3.block_size
KEY_SIZE = 24
# KEY GENERATION
def generate_random_key() -> bytes:
    while True:
        try:
            key = get_random_bytes(KEY_SIZE)
            return DES3.adjust_key_parity(key)

        except ValueError:
            continue
def generate_key_from_password(password: str) -> bytes:
    hash_bytes = hashlib.sha256(
        password.encode('utf-8')
    ).digest()
    return DES3.adjust_key_parity(hash_bytes[:24])
# ENCRYPTION
def encrypt_message(plaintext: str, key: bytes) -> str:
    plaintext_bytes = plaintext.encode('utf-8')
    padded_plaintext = pad(
        plaintext_bytes,
        BLOCK_SIZE
    )
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = DES3.new(
        key,
        DES3.MODE_CBC,
        iv
    )
    ciphertext = cipher.encrypt(padded_plaintext)
    combined_data = iv + ciphertext
    return base64.b64encode(
        combined_data
    ).decode('utf-8')
# DECRYPTION
def decrypt_message(ciphertext_b64: str, key: bytes) -> str:
    combined_data = base64.b64decode(
        ciphertext_b64.encode('utf-8')
    )
    iv = combined_data[:BLOCK_SIZE]
    ciphertext = combined_data[BLOCK_SIZE:]
    cipher = DES3.new(
        key,
        DES3.MODE_CBC,
        iv
    )
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(
        padded_plaintext,
        BLOCK_SIZE
    )
    return plaintext.decode('utf-8')
# DISPLAY HELPER
def display_result(label: str, value: str):
    print(f"  {label:<20}: {value}")
# MAIN PROGRAM
def main():
    print('=' * 65)
    print('     SECURE MESSAGE ENCRYPTION USING TRIPLE DES')
    print('=' * 65)
    print('\n[STEP 1] KEY CONFIGURATION')
    print('1. Auto Generate Secure Key')
    print('2. Generate Key From Password')
    choice = input('\nChoose Option (1 or 2): ').strip()
    if choice == '2':
        password = input('Enter Password: ').strip()
        key = generate_key_from_password(password)
        print('\nDerived Key (HEX):')
        print(key.hex())
    else:
        key = generate_random_key()
        print('\nGenerated Key (Base64):')
        print(base64.b64encode(key).decode())
    print('\n[STEP 2] MESSAGE INPUT')
    plaintext = input('Enter Message: ').strip()
    if not plaintext:
        print('ERROR: Message cannot be empty.')
        return
    print('\n[STEP 3] ENCRYPTION')
    start = time.perf_counter()
    encrypted_text = encrypt_message(
        plaintext,
        key
    )
    encryption_time = (
        time.perf_counter() - start
    ) * 1000
    display_result('Original Message', plaintext)
    display_result('Encrypted Message', encrypted_text)
    print(f'\n  Encryption Time   : {encryption_time:.4f} ms')
    print('\n[STEP 4] DECRYPTION')
    start = time.perf_counter()
    decrypted_text = decrypt_message(
        encrypted_text,
        key
    )
    decryption_time = (
        time.perf_counter() - start
    ) * 1000
    display_result('Decrypted Message', decrypted_text)
    print(f'\n  Decryption Time   : {decryption_time:.4f} ms')
    print('\n[STEP 5] VERIFICATION')
    if plaintext == decrypted_text:
        print('  SUCCESS — Decrypted message matches original.')
    else:
        print('  FAILURE — Message mismatch detected.')
    print('\n' + '=' * 65)
if __name__ == '__main__':
    main()