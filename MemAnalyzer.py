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
    for line in  gdbwrapper.vmmap():
        print line

    io.interactive()
if __name__ == "__main__":
    main("/bin/cat")
