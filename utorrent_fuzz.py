'''
*DUMB* fuzzer for .torrent files
Feed the process with byte-mutated torrent files and look for crashes. 
It is the dumbest fuzzer ever... But we love him anyway.

Kudos to Justin Seitz and his book!
'''

from pydbg import *
from pydbg.defines import *
from ctypes import *
import utils

import random
import struct
import sys, os
import time, shutil
import threading
import smtplib
import getopt



class Mutator:
    
    def __init__(self, filename):
        
        self.filename = filename
        
        
    def randomize_byte(self):
        '''
        Mutates a file changing just a random byte
        '''
        f = open(self.filename, 'rb')
        f_bytes = f.read()
        f.close()
        f_len = len(f_bytes) - 1 # idx: (0, N - 1)
        position = random.randint(0, f_len)
        mutant = random.randint(0, 255)
        print "[debug] pos: %04x, value: %02x" % (position, mutant)
        new_bytes = f_bytes[0:position] + struct.pack('B', mutant) + f_bytes[position + 1:]
        filenameMutant = "S:\\Possible_Victims\\_btguard\\TorrentFilesToMutate\\test.torrent"
        f = open(filenameMutant, 'wb')
        f.write(new_bytes)
        f.close()
        
        return True


class uTorrentFuzzer:
    
    def __init__(self, modulePath, email = False):
        
        self.modulePath = modulePath # Path to the .exe
        self.crash      = None
        self.dbg        = None
        self.running    = None
        self.crashed    = None
        self.mutated_file = "S:\\Possible_Victims\\_btguard\\TorrentFilesToMutate\\test.torrent"
        self.in_accessv_handler = False
        self.pid        = None
        self.iteration  = 0
        self.running    = False
        self.email      = email
        
        
        
        # Drop me a line :)
        self.smtpserver = 'smtp.gmail.com'
        self.recipient  = 'carlos.g.prado@gmail.com'
        self.sender     = 'crashhunter@brundlelab.org'
        
        
    def chooseFile(self):
        ''' Gets a file from our sample directory '''
        
        file_list = os.listdir("S:\\Possible_Victims\\_btguard\\TorrentFilesToMutate")
        list_len = len(file_list)
        file = file_list[random.randint(0, list_len - 1)]
        
        filePath = "S:\\Possible_Victims\\_btguard\\TorrentFilesToMutate\\" + file
        return filePath
    
            
    def fuzzLoop(self):
        ''' Launch the debugger and monitoring threads'''
        
        while 1:
            
            if not self.running:
                
                self.sample_file = self.chooseFile()
                mutator = Mutator(self.sample_file)
                mutator.randomize_byte()
                
                # Debugger thread
                pydbg_thread = threading.Thread(target = self.debug_process)
                pydbg_thread.setDaemon(0)
                pydbg_thread.start()
                
                # As long as there's no process attached
                # we can't launch a monitor thread
                while self.pid == None:
                    time.sleep(1)
                
        
                # Monitor thread
                monitor_thread = threading.Thread(target = self.monitor_debugger)
                monitor_thread.setDaemon(0)
                monitor_thread.start()
                
                self.iteration += 1
                
            else:
                time.sleep(1)



    def debug_process(self):
        
        self.running = True
        self.dbg = pydbg()
        # Install our custom handler
        self.dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, self.accessv_handler)
        self.dbg.load(self.modulePath, self.mutated_file)
        
        self.pid = self.dbg.pid
        self.dbg.run()
        
        
        
    def accessv_handler(self, dbg):
        '''@note: pydbg object is received implicitly'''
        
        if dbg.dbg.u.Exception.dwFirstChance:
            return DBG_CONTINUE
        
        print "[!] Access violation detected!"
        
        self.in_accessv_handler = True # Don't kill me, I'm handling it!
        crash_bin = utils.crash_binning.crash_binning()
        crash_bin.record_crash(dbg)
        self.crash = crash_bin.crash_synopsis()
        
        # Write crash information
        crash_fd = open("crashes\\crash_info_%d" % self.iteration, "w")
        crash_fd.write(self.crash)
        
        # Save the file for further analysis
        shutil.copy(self.mutated_file, "S:\\Possible_Victims\\_btguard\\crashes\\crash_file_%d" %self.iteration)
        # Even send me an email!
        if self.email:
            self.email_me()
        
        # Not interested in what happens next. Just terminate the
        # process and start over again later!
        self.dbg.terminate_process()
        self.in_accessv_handler = False # OK, I'm done :)
        self.running = False
        
        return DBG_EXCEPTION_NOT_HANDLED
        
        
        
    def monitor_debugger(self):
        '''
        Allows the app to run for a few seconds and then kill it
        if it did not die for itself.
        '''
        time.sleep(4)
        
        if self.in_accessv_handler != True:
            time.sleep(1)
            self.dbg.terminate_process()
            self.pid = None  # Reset
            self.running = False
        else:
            # Access violation handler is working...
            while self.running:
                time.sleep(1)
                
    def email_me(self):
        '''Take a wild guess :)'''
        
        crash_message = "From:%s\r\n" % self.sender
        crash_message += "To:%s\r\n" % self.recipient
        crash_message += "Iteration:%d\n" % self.iteration
        crash_message += "Output:\n\n %s" % self.crash
        
        session = smtplib.SMTP(self.smtpserver)
        session.sendmail(self.sender, self.recipient, crash_message)
        session.quit()
        
        return True
    
    
    
if __name__ == '__main__':
    
    
    def usage():
        print "Usage:"
        print "[x] utorrent_fuzz.py -e <.exe path> -n (for email notification)"
        
        
    try:
        opts, args = getopt.getopt(sys.argv[1:], "e:x:n")
    except getopt.GetoptError:
        usage()
        
    exe_path = None
    email = False
    
    for o,a in opts:
        if o == '-e':
            exe_path = a
        elif o == '-n':
            email = True
    
    if exe_path is not None:
        fuzzer = uTorrentFuzzer(exe_path, email)
        fuzzer.fuzzLoop()
    else:
        usage()
         