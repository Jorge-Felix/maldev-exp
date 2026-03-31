import sys, os

def bin2c(path, var="shellcode"):
    data = open(path, "rb").read()
    lines = []
    for i in range(0, len(data), 12):
        chunk = data[i:i+12]
        lines.append("    " + ", ".join(f"0x{b:02X}" for b in chunk) + ",")

    lines[-1] = lines[-1].rstrip(",")

    print(f"unsigned char {var}[] = {{")
    print("\n".join(lines))
    print(f"}};\n")
    print(f"unsigned int {var}_len = sizeof({var});  // {len(data)} bytes")

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "shellcode.bin"
    if not os.path.isfile(path):
        sys.exit(f"[!] {path} not found")
    bin2c(path)
