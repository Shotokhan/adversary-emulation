import sys


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} filename n_bytes")
        exit(1)
    filename = sys.argv[1]
    n_bytes = sys.argv[2]
    if '0x' in n_bytes:
        n_bytes = int(n_bytes, 16)
    else:
        n_bytes = int(n_bytes)
    with open(filename, 'rb') as f:
        data = f.read()
    assert len(data) >= n_bytes
    data = data[:n_bytes]
    with open(filename, 'wb') as f:
        f.write(data)

