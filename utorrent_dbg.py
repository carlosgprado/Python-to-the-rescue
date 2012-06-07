'''
PyDBG spying (hooks are beautiful) on 
kernel32!CreateFile
kernel32!ReadFile and 
kernel32!SetFilePointer


CreateFile() -> handle
ReadFile(handle)
SetFilePointer(handle)
CloseHandle(handle)
'''

from pydbg import *
from pydbg.defines import *
from ctypes import *

from string import *


import sys
import utils
import struct



__VERSION__ = '0.4'


class UtorrentHooker:
    
    def __init__(self):
        
        # Some global stuff
        self.TFileName = 'poison.torrent'
        self.pid_utorrent = 0
        self.dbg = None

        # Let's define a list of handles in case there's more
        # than one call to ReadFile for the same file
        self.handleList = list()
        
        # Offsets pos:[len, name] within .torrent file
        self.InterestingOffsets = {
                                    3:[43, "Tracker"], 
                                    126:[10, "Length"],
                                    157:[18, "Piece Length"], 
                                    179:[30, "Pieces"]
                                    }
        

    def debugger_init(self):
        '''
        The name says it all, doesn't it?
        '''
        
        self.dbg = pydbg()
        
        # Find the process' PID.
        # Search by name.
        plist = self.dbg.enumerate_processes()
        
        for p in plist:
            if p[1] == "utorrent.exe":
                self.pid_utorrent = p[0]
                print "Found utorrent.exe - PID %d" % p[0]
        
                
        # Attach to the process.
        self.dbg.attach(int(self.pid_utorrent))
        
        # Define the hook container.
        hooks = utils.hook_container()
        
        # Resolve the interesting function's addresses.
        CreateFileAddr    = self.dbg.func_resolve("kernel32.dll", "CreateFileW")    # Exit Hook: handle
        ReadFileAddr    = self.dbg.func_resolve("kernel32.dll", "ReadFile")        # Entry Hook: check right handle
        CloseHandleAddr = self.dbg.func_resolve("kernel32.dll", "CloseHandle")    # Exit Hook: erase closed handles
        
        # SET the hooks!
        hooks.add(self.dbg, CreateFileAddr, 7, None, self.CreateFileHook)        # Exit hook
        hooks.add(self.dbg, ReadFileAddr, 5, self.ReadFileHook, None)            # Entry hook
        hooks.add(self.dbg, CloseHandleAddr, 1, None, self.CloseHandleHook)        # Exit hook
        print "[x] Hooks added!"
        
        
        # Let the program run!
        print "[x] Here we go!"
        self.dbg.run()



    def CreateFileHook(self, dbg, args, ret):
        '''
        Exit hook.
        Get the handle used internally to access our .torrent file    
        '''
        
        sPATH = self.dbg.smart_dereference(args[0])
        
        if sPATH.find(self.TFileName) >= 0:
            self.handleList.append(ret)
            print "[debug] %s accessed. Handle: %d" % (self.TFileName, ret)
            print "[debug] Desired Access: %08x" % args[1]
        
        
        return DBG_CONTINUE
        
    
    
    def ReadFileHook(self, dbg, args):
        '''
        Entry hook. 
        Check if the handle corresponds to our file. Breakpoint and
        initial analysis (disass) is performed.
        '''
        handle = args[0]
        if handle in self.handleList:
            # Get the *current* file pointer with this trick
            # "From current position (1) move zero."
            # Function returns the updated pointer.
            curFilePtr = windll.kernel32.SetFilePointer(handle, 0, 0, 1)
            last_error = windll.kernel32.GetLastError()
            print "[x] debug: handle: %08x" % handle
            print "[x] debug: buffer: %08x" % args[1]
            print "[x] debug: nrBytesToRead: %08x" % args[2]
            print "[x] debug: FilePtr:", curFilePtr
            print "[x] debug: Last Error:", last_error
            
            for k in self.InterestingOffsets.keys():
                if curFilePtr in range(k, k + self.InterestingOffsets[k][0] + 1):
                    print "[*] ReadFile() one of the *interesting* offsets!"
                    print "[*] Read the %s offset!" % self.InterestingOffsets[k][1]
                    print "[*]"
                    print "[*] Info around current EIP (%08x)" % self.dbg.context.Eip
                    print "[*] ------------------------------\n"
                    print "%s" % self.dbg.dump_context()
                    
                    callerAddr = self.dbg.read_process_memory(self.dbg.context.Esp, 4)
                    callerAddr = struct.unpack("L", callerAddr)[0]
                    print "[*] Called from: %08x" % callerAddr
                    
                    # Who doesn't like a beautiful disassembly?
                    for (addr, disas) in self.dbg.disasm_around(callerAddr):
                        print "%08x: %s" % (addr, disas)
            
        
        return DBG_CONTINUE
    
    
    
    def CloseHandleHook(self, dbg, args, ret):
        '''
        Exit hook.
        Check if some of our handles has been closed by the program and erases it 
        from the list. Keep things clear.
        '''
        
        handle = args[0]
        if handle in self.handleList:
            print "[debug] Remove handle", handle
            self.handleList.remove(handle)
        
        
        return DBG_CONTINUE


###############################################################################
if __name__ == '__main__':
    
    debugger = UtorrentHooker()
    print "Initializing UtorrentHooker ;)"
    debugger.debugger_init()
    