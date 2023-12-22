from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
import multiprocessing as mp
import time
import ctypes


BLOCK_SIZE = 8


def init_encrypt(shared_data, output_data, block_size, key, iv):
    mp.shared_data = shared_data
    mp.output_data = output_data
    mp.block_size = block_size
    mp.key = key
    mp.iv = iv


def init_decrypt(shared_data, output_data, block_size, key, iv):
    mp.shared_data = shared_data
    mp.output_data = output_data
    mp.block_size = block_size
    mp.key = key
    mp.iv = iv


def mapper_enrypt(blocks):
    plain_text = mp.shared_data
    cipher_text = mp.output_data
    block_size = mp.block_size
    iv = mp.iv
    des = DES.new(mp.key, DES.MODE_CTR, nonce=b"", initial_value=iv)

    for i in blocks:
        offset = i * block_size
        block = plain_text[offset : offset + block_size]
        decrypted = des.encrypt(bytes(block))
        cipher_text[offset : offset + block_size] = decrypted
    return i


def mapper_decrypt(blocks):
    cipher_text = mp.shared_data
    plain_text = mp.output_data
    block_size = mp.block_size
    iv = mp.iv
    des = DES.new(mp.key, DES.MODE_CTR, nonce=b"", initial_value=iv)

    for i in blocks:
        offset = i * block_size
        block = cipher_text[offset : offset + block_size]
        decrypted = des.decrypt(bytes(block))
        plain_text[offset : offset + block_size] = decrypted
    return i


def encrypt_message_time(key, iv, plain_text):
    no_blocks = int(len(plain_text) / BLOCK_SIZE)
    W = mp.cpu_count()

    shared_data = mp.RawArray(ctypes.c_ubyte, plain_text)
    output_data = mp.RawArray(ctypes.c_ubyte, plain_text)
    blocks = [range(i, no_blocks, W) for i in range(W)]

    pool = mp.Pool(
        W,
        initializer=init_encrypt,
        initargs=(shared_data, output_data, BLOCK_SIZE, key, iv),
    )
    starttime = time.time()
    pool.map(mapper_enrypt, blocks)
    encrypt_time = time.time() - starttime
    encrypted = bytes(output_data)

    return encrypted, encrypt_time


def decrypt_message_time(key, iv, encrypted):
    no_blocks = int(len(encrypted) / BLOCK_SIZE)
    W = mp.cpu_count()

    shared_data = mp.RawArray(ctypes.c_ubyte, encrypted)
    output_data = mp.RawArray(ctypes.c_ubyte, encrypted)
    blocks = [range(i, no_blocks, W) for i in range(W)]

    pool = mp.Pool(
        W,
        initializer=init_decrypt,
        initargs=(shared_data, output_data, BLOCK_SIZE, key, iv),
    )
    starttime = time.time()
    pool.map(mapper_decrypt, blocks)
    decrypt_time = time.time() - starttime
    decrypted = bytes(output_data)

    return decrypted, decrypt_time


def compare_times_for_sizes():
    key, iv = (get_random_bytes(BLOCK_SIZE), get_random_bytes(BLOCK_SIZE))
    sizes = [10_000, 100_000, 1_000_000, 10_000_000, 100_000_000]
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
        encrypted, encrypt_time = encrypt_message_time(key, iv, data["data"]["message"])
        data["data"]["time_encryption"] = encrypt_time

        decrypted, decrypt_time = decrypt_message_time(key, iv, encrypted)
        data["data"]["time_decryption"] = decrypt_time

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

    encrypted, encrypt_time = encrypt_message_time(key, iv, plain_text)
    print(f"Encrypted: {encrypted[-10:]}")
    print(f"Encrypt time: {encrypt_time}")

    decrypted, decrypt_time = decrypt_message_time(key, iv, encrypted)
    print(f"Decrypted: {decrypted[-10:]}")
    print(f"Decrypt time: {decrypt_time}")
