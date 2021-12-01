for i in $(find -type f); do for x in $(cat grep.txt); do $x $i >> $(date +"%d-%b-%Y").output; echo "\n\n" >> $(date +"%d-%b-%Y").output; done; done
