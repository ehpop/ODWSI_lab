import sys
import re
import math
import string
from Crypto.Cipher import ARC4


def get_entropy(text):
    statistics = {}
    length = len(text)

    for char in text:
        if char in statistics:
            statistics[char] += 1
        else:
            statistics[char] = 1

    entropy = 0.0

    for char in statistics:
        probability = statistics[char] / length
        entropy -= probability * math.log2(probability)

    return entropy


def main():
    ciphertext = open("lab_1/cipher.5", "rb").read()

    entropies = {}
    letters = string.ascii_lowercase

    all_keys = [letter1 + letter2 +
                letter3 for letter1 in letters for letter2 in letters for letter3 in letters]

    for i, key in enumerate(all_keys):
        if i % 1000 == 0:
            print(f"Done {(i / len(all_keys)) * 100}% done")

        cipher = ARC4.new(key.encode('utf-8'))
        decrypted = cipher.decrypt(ciphertext)
        entropies[key] = get_entropy(decrypted)

    min_key, min_value = min(entropies.items(), key=lambda item: item[1])

    print(f"key: '{min_key}' -> {min_value} [entropy]")

    cipher = ARC4.new(min_key.encode('utf-8'))
    decrypted = cipher.decrypt(ciphertext)
    print(f"Decrypted = {decrypted}")


if __name__ == "__main__":
    main()
