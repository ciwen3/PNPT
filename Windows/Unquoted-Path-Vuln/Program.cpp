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


