from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from binascii import b2a_hex
import os


def nullpadding(data, block_size=16):
    padding_length = block_size - len(data) % block_size
    return data + b"\x00" * padding_length


def encrypt_file_with_key(filename, key):
    salt = b"salt"
    iv = get_random_bytes(16)

    with open(filename, "rb") as input_file:
        data = input_file.read()

    data_padded = nullpadding(data)

    key = PBKDF2(key, salt)
    aes = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = aes.encrypt(data_padded)

    if filename == "file_no_padding_needed.txt":
        output_filename = "./output_r.enc"
    elif filename == "file_padding_needed.txt":
        output_filename = "./output_nr.enc"
    else:
        output_filename = "./default.txt"

    with open(output_filename, "wb") as output_file:
        output_file.write(b2a_hex(iv))
        output_file.write(b"\n")
        for i in range(0, len(encrypted_data), 16):
            line = b2a_hex(encrypted_data[i:i + 16])
            output_file.write(line)
            output_file.write(b"\n")

    with open(output_filename, "rb") as result_file:
        print(result_file.read())


# Example usage
encrypt_file_with_key("file_padding_needed.txt", "aaaabbbbccccdddd")
encrypt_file_with_key("file_no_padding_needed.txt", "aaaabbbbccccdddd")
