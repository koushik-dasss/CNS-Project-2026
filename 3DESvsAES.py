from Cryptodome.Cipher import DES3, AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad
import time
import base64

BLOCK_SIZE_3DES = DES3.block_size
BLOCK_SIZE_AES = AES.block_size

def generate_random_key() -> bytes:
    while True: 
        try:
            key = get_random_bytes(24)
            return DES3.adjust_key_parity(key)
        except ValueError:
            continue

def encrypt_3des(message: str, key: bytes):
    iv = get_random_bytes(BLOCK_SIZE_3DES)
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    padded_message = pad(message.encode(), BLOCK_SIZE_3DES)
    ciphertext = cipher.encrypt(padded_message)
    return base64.b64encode(iv + ciphertext)

def benchmark_3des(key: bytes):
    print('\n[3DES PERFORMANCE BENCHMARK]')
    message_sizes = [100, 1000, 10000, 100000]
    repetitions = 10
    print(f"\n{'Message Size':<18}{'Encrypt Time':>20}")
    print('-' * 40)
    for size in message_sizes:
        message = 'A' * size
        execution_times = []
        for _ in range(repetitions):
            start = time.perf_counter()
            encrypt_3des(message, key)
            end = time.perf_counter()
            execution_times.append(end - start)
        average_time = (sum(execution_times) / repetitions) * 1000
        print(f"{str(size) + ' bytes':<18}{average_time:>15.4f} ms")

def compare_3des_vs_aes():
    print('\n[3DES VS AES COMPARISON]')
    key_3des = generate_random_key()
    key_aes = get_random_bytes(16)
    message = ('A' * 100000).encode()
    repetitions = 10
    aes_times = []
    for _ in range(repetitions):
        iv = get_random_bytes(BLOCK_SIZE_AES)
        cipher = AES.new(key_aes, AES.MODE_CBC, iv)
        start = time.perf_counter()
        cipher.encrypt(pad(message, BLOCK_SIZE_AES))
        end = time.perf_counter()
        aes_times.append(end - start)
    aes_average = (sum(aes_times) / repetitions) * 1000
    des_times = []
    for _ in range(repetitions):
        start = time.perf_counter()
        encrypt_3des('A' * 100000, key_3des)
        end = time.perf_counter()
        des_times.append(end - start)
    des_average = (sum(des_times) / repetitions) * 1000
    print(f'\n3DES Encryption Time : {des_average:.4f} ms')
    print(f'AES Encryption Time   : {aes_average:.4f} ms')
    print(f'AES is approximately {des_average / aes_average:.2f}x faster than 3DES')

def main():
    print('=' * 60)
    print('      PERFORMANCE ANALYSIS OF TRIPLE DES')
    print('=' * 60)
    key = generate_random_key()
    benchmark_3des(key)
    compare_3des_vs_aes()
    print('\n' + '=' * 60)

if __name__ == '__main__':
    main()
