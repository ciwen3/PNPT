#!/bin/bash
#attempt to elevate to root 
#
#

echo "Hello World!"


python -c 'import pty;pty.spawn("/bin/bash")'
echo os.system('/bin/bash')
/bin/sh -i
