import sys


def check_arg(argv, arg):
    if arg in argv:
        return True, argv.index(arg)
    else:
        return False, -1


def get_arg(argv, arg, mandatory=False):
    check, ind = check_arg(argv, arg)
    if check:
        if len(argv) <= ind + 1:
            print(f"Argument {arg} expected a value, none given")
            exit(1)
        value = argv[ind + 1]
        if "-" in value:
            print(f"Argument {arg} expected a value, argument given")
            exit(1)
        return True, value
    else:
        if mandatory:
            print(f"Argument {arg} is mandatory")
            exit(1)
        return False, 0


def modify(offset: int, new_data: str, shellcode: bytes, swap_bytes):
    # new_data shall be hex; swap_bytes=True tells to reverse bytes of new_data
    # to inject little endian format; new_data is written in shellcode at offset
    # modified shellcode is returned
    new_data = bytes.fromhex(new_data)
    if swap_bytes:
        new_data = new_data[::-1]
    new_shellcode = b""
    new_shellcode += shellcode[:offset]
    new_shellcode += new_data
    new_shellcode += shellcode[offset+len(new_data):]
    return new_shellcode


def load_shellcode(filename):
    with open(filename, 'rb') as f:
        data = f.read()
    return data
    

def customize(filename, offset, data, swap_bytes, in_place):
    shellcode = load_shellcode(filename)
    new_shellcode = modify(offset, data, shellcode, swap_bytes)
    if in_place:
        new_filename = filename
    else:
        new_filename = f"modified_{filename}"
    with open(new_filename, 'wb') as f:
        f.write(new_shellcode)
    

def main():
    if len(sys.argv) == 1 or check_arg(sys.argv, "-h")[0] or check_arg(sys.argv, "--help")[0]:
        print(f"Usage: {sys.argv[0]} --offset OFFSET --filename FILENAME --data HEX_DATA {{--no-swap-bytes}} {{--in-place}} {{-h --help}}")
    else:
        _, offset = get_arg(sys.argv, "--offset", mandatory=True)
        offset = int(offset)
        _, filename = get_arg(sys.argv, "--filename", mandatory=True)
        _, data = get_arg(sys.argv, "--data", mandatory=True)
        if data.startswith("0x"):
            data = data[2:]
        swap_bytes, in_place = True, False
        if check_arg(sys.argv, "--no-swap-bytes")[0]:
            swap_bytes = False
        if check_arg(sys.argv, "--in-place")[0]:
            in_place = True
        customize(filename, offset, data, swap_bytes, in_place)


if __name__ == "__main__":
    main()
