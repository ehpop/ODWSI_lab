from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from binascii import a2b_hex, b2a_hex


def decrypt_file(key, filename="./output_r.enc"):
    input_file = open(filename, "r")

    iv = a2b_hex(input_file.readline().rstrip())
    lines = [line.rstrip() for line in input_file.readlines()]
    encoded_data = "".join(lines)

    aes = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = aes.decrypt(a2b_hex(encoded_data))
    decrypted_data = decrypted_data.rstrip(b'\x00')

    try:
        print("Decrypted data: {}".format(decrypted_data.decode('utf-8')))
    except UnicodeDecodeError:
        print("Could not convert to utf-8: {}".format(decrypted_data))


correct_key = a2b_hex(b"ca7c88f5ecf260ff22c7ef48f5884a79")
incorrect_key = a2b_hex(b"ffffffffffffffffffffffffffffffff")

print("Correct key and file that was padded:")
decrypt_file(correct_key, "./output_nr.enc")

print("Correct key:")
decrypt_file(correct_key)
print("Incorrect key:")
decrypt_file(incorrect_key)
print("Incorrect IV:")
decrypt_file(correct_key, filename="./output_r_corrupted.enc")
