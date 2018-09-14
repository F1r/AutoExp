from GdbWrapper import GdbWrapper
from examples.tcache_entry import main as tcache_entry_main
from pwn import *
import sys

context.log_level = "info"

def main(binary, poc):
    tcache_entry_main(binary, poc)
if __name__ == "__main__":
    main("./examples/bins/a679df07a8f3a8d590febad45336d031-stkof", "")
