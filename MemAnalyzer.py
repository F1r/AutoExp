from GdbWrapper import GdbWrapper
import signal
import subprocess
import os
from pwn import *

context.log_level = "info"

def main(binary):
    args = [binary]
    io = process(args)
    gdbwrapper = GdbWrapper(io.pid)
    print gdbwrapper.get_value(arg_name="main_arena")

    io.interactive()
if __name__ == "__main__":
    main("/bin/cat")
