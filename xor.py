import sys

def xor_file(input_file, output_file, key):
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        data = f_in.read()
        xored_data = bytearray(data[i] ^ ord(key[i % len(key)]) for i in range(len(data)))
        f_out.write(xored_data)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("[!] usage: python xor_encrypt.py <shellcode.bin> <shellcode.enc.bin> <key>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    key = sys.argv[3]

    xor_file(input_file, output_file, key)
    print(f"[+] encrypted shellcode (key: {key}) saved to {output_file}")
