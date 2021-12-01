## Sticky Bit:

Is mainly used on folders in order to avoid deletion of a folder and its content by other users though they having write permissions on the folder contents. If Sticky bit is enabled on a folder, the folder contents are deleted by only owner who created them and the root user. No one else can delete other users data in this folder(Where sticky bit is set). This is a security measure to avoid deletion of critical folders and their content(sub-folders and files), though other users have full permissions.

## Sticky Bit set:
```
ls -l
-rwxr-xrwt 1 xyz xyzgroup 148 Dec 22 03:46 /opt/dump/
         ^-- Sticky bit with execute permissions set. (lowercase 't')

ls -l
-rwxr-xrwT 1 xyz xyzgroup 148 Dec 22 03:46 /opt/dump/
         ^-- Sticky bit without execute permissions set. (uppercase 'T')
```

## Set Symbolic way:
chmod o+t /opt/dump/

or

chmod +t /opt/dump/

We are setting Sticky Bit(+t) to folder /opt/dump by using chmod command.

## set Numerical way:
chmod 1757 /opt/dump/

Here in 1757, 1 indicates Sticky Bit set, 7 for full permissions for owner, 5 for read and execute permissions for group, and full permissions for others.

## Find Files with SGID set:
find / -perm /1000



## SGID (Set Group ID up on execution):
A special type of file permissions given to a file/folder. Normally in Linux/Unix when a program runs, it inherit’s access permissions from the logged in user. SGID is defined as giving temporary permissions to a user to run a program/file with the permissions of the file group permissions to become member of that group to execute the file. In simple words users will get file Group’s permissions when executing a folder/file/program/command.

SGID is similar to SUID. The difference between both is that SUID assumes owner of the file permissions and SGID assumes group’s permissions when executing a file instead of logged in user inherit permissions. 

## SGID bit:
```
ls -l
-rwxr-sr-- 1 xyz xyzgroup 148 Dec 22 03:46 file1.txt
      ^-- SGID bit with execute permissions set. (lowercase 's')
          Will always run as the group, regardless of the user running the command.

chmod u+s file1.txt
-rwxrwSr-x 1 surendra surendra 0 Dec 27 11:24 file1.txt
      ^-- SGID bit without execute permissions set. (uppercase 'S')
```

## Symbolic way:
chmod g+s file1.txt

sets SGID(+s) to group who owns this file.

## Numerical way:
chmod 2750 file1.txt

Here in 2750, 2 indicates SGID bit’set, 7 for full permissions for owner, 5 for read and execute permissions for group, and no permissions for others. 

## Where is SGID used?
1) When implementing Linux group disk quota. 

## Find Files with SGID set:
find / -perm /2000


## SUID (Set owner User ID up on execution):
A special type of file permissions given to a file. Normally in Linux/Unix when a program runs, it inherit’s access permissions from the logged in user. SUID is defined as giving temporary permissions to a user to run a program/file with the permissions of the file owner rather that the user who runs it. In simple words users will get file owner’s permissions as well as owner UID and GID when executing a file/program/command.

## SUID bit:
```
ls -l
-rwsr--r-- 1 xyz xyzgroup 148 Dec 22 03:46 file1.txt
   ^-- SUID bit with execute permissions set. (lowercase 's')
       Will always run on root, regardless of the user running the command.

chmod u+s file1.txt
-rwSrwxr-x 1 surendra surendra 0 Dec 27 11:24 file1.txt
   ^-- SUID bit without execute permissions set. (uppercase 'S')
```

## set Symbolic way:
chmod u+s file1.txt

Here owner permission execute bit is set to SUID with +s

## set Numerical way:
chmod 4750 file1.txt

Here in 4750, four indicates SUID bit set, seven for full permissions for owner, five for read and execute permissions for group, and no permissions for others.

## Where is SUID used?
1) Where root login is required to execute some commands/programs/scripts.
2) Where you don’t want to give credentials of a particular user, but want to run some programs as the owner.
3) Where you don’t want to use SUDO command, but want to give execute permission for a file/script etc.

## Find Files with SUID Set:
find / -perm /4000


## Find Files with Sticky, SGID & SUID bit set:
find / -perm /7000

## Remove the Sticky, SGID & SUID bits:
chmod 0750 <file/folder>

Here in 0750, zero removes Sticky, SGID & SUID bits, seven for full permissions for owner, five for read and execute permissions for group, and no permissions for others.
