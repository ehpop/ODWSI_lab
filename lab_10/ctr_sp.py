from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
import multiprocessing as mp
import time

BLOCK_SIZE = 8  # Use 16 for AES


def pad_message(message):
    padding_length = BLOCK_SIZE - len(message) % BLOCK_SIZE
    padding = bytes([padding_length] * padding_length)
    return message + padding


def unpad_message(padded_message):
    padding_length = padded_message[-1]
    message = padded_message[:-padding_length]
    return message


def encrypt_message(key, message, iv):
    cipher = DES.new(key, nonce=b"", initial_value=iv, mode=DES.MODE_CTR)
    padded_message = pad_message(message)
    ciphertext = cipher.encrypt(padded_message)
    return iv + ciphertext


def decrypt_message(key, ciphertext, iv):
    cipher = DES.new(key, nonce=b"", initial_value=iv, mode=DES.MODE_CTR)
    ciphertext_sans_iv = ciphertext[BLOCK_SIZE:]
    padded_message = cipher.decrypt(ciphertext_sans_iv)
    message = unpad_message(padded_message)
    return message


def compare_times_for_sizes():
    key, iv = (get_random_bytes(BLOCK_SIZE), get_random_bytes(BLOCK_SIZE))
    sizes = [10_000, 100_000, 1_000_000, 10_000_000, 100_000_000, 1_000_000_000]
    data_rows = []

    for size in sizes:
        data = {
            "size": size,
            "data": {
                "message": get_random_bytes(size),
                "time_encryption": 0,
                "time_decryption": 0,
            },
        }
        data_rows.append(data)

    for data in data_rows:
        start_encryption_time = time.time()
        encrypted = encrypt_message(key, data["data"]["message"])
        end_encryption_time = time.time()
        data["data"]["time_encryption"] = end_encryption_time - start_encryption_time

        start_decryption_time = time.time()
        decrypted = decrypt_message(key, encrypted, iv)
        end_decryption_time = time.time()
        data["data"]["time_decryption"] = end_decryption_time - start_decryption_time

    return (
        {data["size"]: data["data"]["time_encryption"] for data in data_rows},
        {data["size"]: data["data"]["time_decryption"] for data in data_rows},
    )


def print_results(times_encryption, times_decryption):
    print("Times for encryption:")
    for size, time in times_encryption.items():
        print(f"Message size: {size:_}, time: {time:.2f}s")
    print("Times for decryption:")
    for size, time in times_decryption.items():
        print(f"Message size: {size:_}, time: {time:.2f}s")


if __name__ == "__main__":
    key = b"haslo123"
    iv = get_random_bytes(8)
    plain_text = b"ala ma kota" * int(100_000_000 / len(b"ala ma kota"))

    stime = time.time()
    encrypted = encrypt_message(key, plain_text, iv)
    encrypt_time = time.time() - stime
    print(f"Encrypted: {encrypted[-10:]}")
    print(f"Encrypt time: {encrypt_time}")

    stime = time.time()
    decrypted = decrypt_message(key, encrypted, iv)
    decrypt_time = time.time() - stime
    print(f"Decrypted: {decrypted[-10:]}")
    print(f"Decrypt time: {decrypt_time}")
