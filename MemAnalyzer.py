import ptrace.debugger
from GdbWrapper import GdbWrapper
import signal
import subprocess
import sys
from pwn import *

context.log_level = "info"
class MemAnalyzer(object):
    _HeapMap = {"start": 0, "end": 0}
    _CodeMap = {"start": 0, "end": 0}
    _RDatMap = {"start": 0, "end": 0}
    _WDatMap = {"start": 0, "end": 0}
    Maps = []
    def __init__(self, pid, name):
        self.debugger = ptrace.debugger.PtraceDebugger()
        self.process = self.debugger.addProcess(pid, False)
        self.on_debug = True
        self.pid = pid
        self.name = name
        self._Map()
        self._detach()
    def _check_attach(self):
        if self.on_debug == False:
            self.process = self.debugger.addProcess(self.pid, False)
            self.on_debug = True
        else:
            pass
    def _detach(self):
        if self.on_debug == True:
            self.process.detach()
            self.on_debug = False
    def _Map(self):
        self._check_attach()
        self.Maps = self.process.readMappings()
        self.Maps.sort()
        for x in self.Maps:
            try:
                if "[heap]" in x.pathname:
                    self._HeapMap["start"] = x.start
                    self._HeapMap["end"] = x.end
                elif self.name in x.pathname and self._CodeMap["start"] == 0 and self._CodeMap["end"] == 0:
                    self._CodeMap["start"] = x.start
                    self._CodeMap["end"] = x.end
                elif self.name in x.pathname and x.start >= self._CodeMap["end"]:
                    self._RDat["start"] = x.start
                    self._RDat["end"] = x.end
                elif self.name in x.pathname and x.start >= self._RDatMap["end"]:
                    self._WDate["start"] = x.start
                    self._WData["end"] = x.end
            except:
                pass
        return self.Maps
    def HeapMap(self):
        self._check_attach()
        self._Map()
        self._detach()
        return self._HeapMap
    def CodeMap(self):
        self._check_attach()
        self._Map()
        self._detach()
        return self._CodeMap
    def RDat(self):
        self._check_attach()
        self._Map()
        self._detach()
        return self._RDat
    def WDate(self):
        self._check_attach()
        self._Map()
        self._detach()
        return self._WDate


def main(binary):
    args = [binary]
    io = process(args)
    MA = MemAnalyzer(pid = io.pid, name=binary)
    HeapStart = MA.HeapMap()["start"]
    gdbwrapper = GdbWrapper(io.pid)
    res = gdbwrapper.get_value("main_arena.bins")

    print res
    io.interactive()
if __name__ == "__main__":
    main("/bin/cat")
