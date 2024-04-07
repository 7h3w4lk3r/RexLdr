import sys
import random

def rc4_encrypt(data, key):
    S = list(range(256))
    j = 0
    out = []

    # Key-Scheduling Algorithm
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    # Pseudo-Random Generation Algorithm
    i = j = 0
    for char in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(char ^ S[(S[i] + S[j]) % 256])

    return out

def generate_random_key(length):
    return [random.randint(0, 255) for _ in range(length)]

def main():
    if len(sys.argv) != 2:
        print("Usage: python encrypt_file.py <binary_file>")
        sys.exit(1)

    input_file = sys.argv[1]

    try:
        with open(input_file, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        print(f"File '{input_file}' not found.")
        sys.exit(1)

    # Encrypt file with RC4 using random key
    random_key = generate_random_key(16)  # You can adjust the key length as needed
    encrypted_data = rc4_encrypt(data, random_key)

    # Print encrypted shellcode and key in the specified format
    print("unsigned char Payload[] = {")
    for i, byte in enumerate(encrypted_data):
        if i % 16 == 0:
            print("\t", end="")
        print(f"0x{byte:02X}, ", end="")
        if (i + 1) % 8 == 0:
            print("")
    print("\n};")

    print("\nunsigned char Key[] = {")
    for i, byte in enumerate(random_key):
        if i % 8 == 0:
            print("\t", end="")
        print(f"0x{byte:02X}, ", end="")
        if (i + 1) % 8 == 0:
            print("")
    print("};")

if __name__ == "__main__":
    main()
