from passlib.hash import sha1_crypt
import itertools
import string

# Constants
length = 5
pierwsze = 7

def get_hash(text):
    return sha1_crypt.hash(text, rounds=1, salt="aaaa")[13:13 + pierwsze]

def generate_words(length):
    return [''.join(w) for w in itertools.product(string.ascii_lowercase, repeat=length)]

def find_collisions(words):
    word_and_hash = {}
    
    for i, word in enumerate(words):
        if i % 10_000 == 0:
            print(f"Done {(i / len(words)) * 100:.2f}% of words", end="\r", flush=True)
        
        first_chars_of_hash = get_hash(word)
        if first_chars_of_hash in word_and_hash:
            return word, word_and_hash[first_chars_of_hash]
        word_and_hash[first_chars_of_hash] = word
    
    return None, None

if __name__ == "__main__":
    all_possible_words = generate_words(length)
    print("Generated all possible words")
    
    word1, word2 = find_collisions(all_possible_words)
    
    if word1 and word2:
        print(f"Found two different words with the same first {pierwsze} characters of their SHA-1 hash:")
        print(f"Word 1: {word1}")
        print(f"Word 2: {word2}")
    else:
        print("No collisions found.")
