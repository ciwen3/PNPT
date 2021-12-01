# Active Directory:
Evalutation Copies of Windows for testing purposes: 
1. https://www.microsoft.com/en-us/evalcenter/
2. https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server
3. https://www.microsoft.com/en-us/evalcenter/evaluate-windows-10-enterprise

alternative resource: 
1. https://evotec.xyz/the-only-powershell-command-you-will-ever-need-to-find-out-who-did-what-in-active-directory/
2. https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet#active-directory-exploitation-cheat-sheet

## Domain Controller
1. hosts a copy of AD Directory Services directory store
2. provide authentication and authorization
3. replicate updates to other domain controllers in the domain and forest
4. allow administrative access to manage user accounts and network resources

## Domains: a way to group and manage objects in an organization
1. an administrative boundary for applying policies to groups of objects
2. a replication boundary for replicating data between domain controllers
3. an authentication and authorization boundary that proveides a way to limit the scope of access to resources. 

## Forest: a collection of one or more domain trees
1. share a common schema
2. share a common configuration partition
3. share a common global catalog to enable searching
4. enable trusts between all domains in the forest
5. share the Enterprise Admins and Schema Admins groups

## Oganizational Unit (OU): OUs are Active Directory containers that can contain users, groups, computers, and other OUs
1. represent your organization hierarchically and logically
2. manage a collection of objects in a consistent way
3. delegate permissions to administer groups of objects
4. apply policies

## Trusts: provide a mechanism for users to gain access to resources in another domain
1. all domians in a forest trust all other domains in the forest
2. trust can extend outside the forest

Directional Trust: the trust direction flows from trusting domain to to trusted domain

Transitive Trust: the trust relationship is extended beyond a two-domain trust to include other trusted domains 

## Objects:
1. User: enables network resource access for a user
2. InetOrgPerson: similar to user account, used for compatibility with other directory services
3. Contacts: Used primarily to assign e-mail addresses to external users, doesn't enable network access
4. Groups: used to simplify the administration of access controls
5. Computers: Enables authentication and auditing of computer access to resources
6. Printers: Used to simplify the process of locating and connecting to printers
7. Shared Folders: enables users to search for shared folders based on properties


**********************

## Active Directory Domain Controller Setup:
1. Install server using Windows server 2019 evaluation iso
2. Rename server (reboot)
4. Install Active Directory:
  - Manage > add Roles and Features > Next > Next > Next > Active Directory Domain Services > Next ... Install
6. Promote this server to a domain controller
  - After Installation has finished, look for Yellow Flag (Post-deployment Configuration)
5. Add a New Forest > Root Domain Name: MARVEL.local (Strat0m.com or whatever domain you want) > Create Password > Next > wait for Domain name to show up then choose Next > Next (can change NTDS location if wanted) > Next > Install
  - will automatically reboot server

## Active Directory Add File Share:
Server Manager > File and Storage Service (left pane)
Shares > Tasks (drop down window) > New Share... > SMBshare Quick > Next > Share Name: HackMe > Next > Next > Create (opens up ports 139 and 445)

## Create Service Prinicple Name (SPN): kerberoasting? 
CMD (run as administrator) 
```
setspn -a HYDRA-DC/SQLService.MARVEL.local:60111 Marvel\SQLService
setspn -T MARVEL.local -Q */*
```
## Active Directory Add Group Policy: to turn of Defender Anti-Virus
1. Group Policy Management 
2. Forest: Marvel.local > Domains > Marvel.local
3. Right click Marvel.local and select "Create a GPO in this domian, and link it here..."
  - Name the GPO: Disable Windows Defender
4. Edit the GPO
  - in Left Pane: Computer Configuration > Policies > Administrative Templates: Policy deinitions (ADM) > Windows Components > Windows Defender Antivirus
  - in right pane: Turn off Windows Defender Antivirus > Enabled > Apply

## Active Directory Add Users:
1. Server Manager > Tools > Active Directory Users and Computers 
2. Move all Built-in Security Groups to their own area
  - right click Marvel.local > New > Organizational Unit > name it: Groups
  - Marvel.local > Users 
  - select all except (Administrator and Guest) and move them to the newly greated Groups folder (note down arrow means account has been disabled)
3. right click Marvel.local > New > User (create various users with different levels of access for testing purposes, add a description that includes a password to one account)

## Setting up LDAPS:
1. Server Manager > Manage > add roles and features
2. Next > Next > Next > Active Directory Certificate Services > Next > Next > Next Check Certifcation Authority (Role Services) > Restart the destination server automatically > Yes > Install
3. Yellow Flag at top (Refresh Dashboard if needed) >  Configure Active Directory Certificate Services
4. Next > Check "Certification Authority"  > Next > Next > Next ... Valid Period set to: 99 years > Next > Next > Configure


## Windows 10 connected to Active Directory Domain Controller:
1. Install Windows 10 using evaluation iso 
2. Add User with "Domain Join Instead" (bottom left corner) 
  - This user won't matter once we are joined to the domain
4. Rename computer (reboot)
5. Add File Share (for exploitation purposes)
6. Join to Domain
  - Change DNS settings to point to Domain Controller IP 
  - Start menu > Type: Domain > Access work or school > Connect > Join this Device to a Local Active Directory Domain 
  - Domain Name: Marvel.local 
  - Use Administrator username and password
  - Skip add an account option
  - Restart Now

## Set user as local admin on Winodws 10 PC
1. Login as Administrator 
2. Right click start menu > Computer Management > Local Users and Groups > Groups > Administrators
3. check user name that you want to make admin > OK > Apply

## Windows 10 allow Network discovery
1. Open File Explorer
2. Click Network in the left Pane
3. Clcik "OK" to allowing Network discovery
4. At the top of Explorer: "Turn on network discovery and file sharing"
