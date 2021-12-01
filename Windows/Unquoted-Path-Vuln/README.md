# Program.exe for Unquoted Path Vulnerability

## C++ code:
```
#include <iostream>
#include <string>
#include <cstdlib>

using namespace std;

int main()
{
    // declaring variables:
    string line;
    string  pid;

    // print information:
    printf("This Program was created by Christopher Iwen AKA Strat0m\nto find unquoted path vulnerabilities in Windows programs\nyou can download the source code for this at https://github.com/ciwen3/Public\n\n");


    // run commands:
    printf("User this command was run as:\n");
    system("whoami");
    printf("\n");
    system("whoami /priv");
    printf("\n");
    printf("To find the command that called Program.exe run:\n");
    printf("wmic process where name='program.exe' get commandline\n");
    system("wmic process where name='program.exe' get commandline");
    printf("\n");
    printf("To find the process ID for the command that called Program.exe run:\n");
    printf("wmic process where name='program.exe' get parentprocessid\n");
    system("wmic process where name='program.exe' get parentprocessid");
    printf("\n");
    cout << "type the number that was returned by the last command: ";
    cin >> pid;
    printf("To find the location of the Program that called Program.exe run:\n");
    printf(("wmic process where processid="+pid+" get commandline\n").c_str());
    system(("wmic process where processid="+pid+" get commandline").c_str());
    printf("\n");
    system("pause");
    return 0;
}
```

## To Compile C++ using Linux to make Program.exe
Create 64-Bit Executable
```
x86_64-w64-mingw32-g++ -static-libstdc++ -static-libgcc -o Program.exe Program.cpp
```
Create 32-Bit Executable
```
i686-w64-mingw32-g++ -static-libstdc++ -static-libgcc -o Program.exe Program.cpp
```

## Accidentally Find Vulnerabilites
Place Program.exe in C:\ on a windows machine. If a program with an unquoted path vulnerability runs it will end up trying to call C:\Program.exe. 

This flaw exists because of how Windows searches for programs that contain a space in the name. For instance when trying to call C:\Program Files (x86)\Some Program\run.exe without any quotes, Windows will do so in this order:
```
C:\Program.exe
C:\Program Files.exe
C:\Program Files (x86)\Some.exe
C:\Program Files (x86)\Some Program\run.exe 
```
By placing my program in C:\Program.exe the vulnerable program will cause my program to run and give you the name of the user it was run as, what privileges the user has, what command was used to start Program.exe, the Process ID for that Command, and the location of the application that ran the command. 

## Intentionally Find Vulnerabilites
open CMD and run:
```
wmic service get pathname,startname
```
you are looking for programs that have a space in the path name. 

rename program.exe to what ever you need and put in the proper place. then run that program. 


