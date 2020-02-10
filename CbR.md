# Carbon Black

## CarbonBlack Course - Queries

### Reconnaissance, Weaponization and Delivery

#### Malicious Code Download and Execution from Browsers and Exploited Applications

##### Child processes of exploitable Browsers and Plugins (Java/Flash)

```yaml
alliance_score_nvd:* AND childproc_count:[1 TO *]
```

##### Child Processes of cmd.exe or powershell.exe

```yaml
parent_name:powershell.exe or parent_name:cmd.exe
```

##### Putting it together

```yaml
alliance_score_nvd:* AND (childproc_name:powershell.exe OR childproc_name:cmd.exe)
```

#### Processes launching from Non-standard paths that are Non-Signed

```yaml
-path:C* AND -path:D* and -digsig_result:"Signed"
```

#### Spear Phishing

##### Untrusted Child Processes of Email Clients

```yaml
-alliance_score_srstrust:* AND (parent_name:outlook.exe OR parent_name:eudora.exe OR parent_name:thunderbird.exe)
```

##### View Outlook Email Attachments

```yaml
filemod:Content.Outlook\*
```

##### Malicious Word Docs

```yaml
parent_name:winword.exe AND process_name:cmd.exe AND childproc_name:wscript.exe
```

#### Other

##### Metasploit Meterpreter using the windows/smb/psexec exploit

```yaml
childproc_name:"rundll32.exe" AND digsig_result:"Unsigned" AND path:c:\Windows\*
```

##### Malicious PowerShell Usage

```yaml
process_name:powershell.exe AND netconn_count:[1 TO *] AND (cmdline:"-Enc" OR cmdline:"-Exec" OR cmdline:"bypass" OR cmdline:"hidden")
```

##### Sample Administrative Tools that can be used to probe environment

```yaml
net.exe whoami.exe enum.exe sc.exe netsh.exe arp.exe reg.exe nmap.exe tasklist.exe tracert.exe ping.exe netstat.exe psexec.exe
```

### Exploitation and Installation

#### Establish Persistence

##### Service Creation

```yaml
cmdline:"sc create" OR regmod:services*
```

##### RunKeys updates

```yaml
regmod:CurrentVersion\Run*
```

##### Scheduled Tasks/At Jobs

```yaml
parent_name:taskeng.exe OR process_name:at.exe OR process_name:schtasks.exe
```

##### StartMenu updates

```yaml
filemod:"Start Menu\Programs\Startup"
```

#### Privilege Escalation

##### Instances of "net user"

```yaml
cmdline:"net user" OR cmdline:"net create"
```

##### wce.exe

```yaml
process_name:wce.exe
```

##### RunAs.exe

```yaml
process_name:runas.exe OR cmdline:runas
```

##### wmic.exe

```yaml
process_name:wmic.exe
```

#### Obfuscation

##### Compilers executing on non-developer workstations

```yaml
(process_name:javac.exe OR process_name:gcc*) AND (filemod:appdata OR filemod:temp OR filemod:windows OR filemod:users) AND -group:Developers
```

##### Execution from Recycle Bin

```yaml
path:$recycle*
```

#### Other

##### Binaries/Processes NOT Trused by CarbonBlack

```yaml
-alliance_score_srstrust:*
```

### Command and Control (C2)

#### Intercepting Communication and Instructions

##### Programs launched from a shell or scropt that is network aware and not trusted

```yaml
(parent_name:powershell.exe OR parent_name:cmd.exe) AND netconn_count:[1 TO *] AND -alliance_score_srstrust:*
```

##### Services that are Network Aware and not trusted

```yaml
parent_name:services.exe AND netconn_count:[1 TO *] AND -alliance_score_srstrust:*
```

##### Scheduled Tasks that are Network Aware and not trusted

```yaml
parent_name:taskeng.exe AND netconn_count:[1 TO *] AND -alliance_score_srstrust:*
```

##### Non Browsers Connecting to Suspicious Nation State domains

```yaml
(domain:.cn OR domain:.ru OR domain:.ir) AND -process_name:iexplore.exe AND -process_name:firefox.exe AND -process_name:chrome.exe AND -process_name:opera.exe
```

#### Other

##### All external network connections

```yaml
ipaddr:[0 TO 167772159] OR ipaddr:[184549376 TO -1073741825] OR ipaddr:[-1056964608 TO -1]
```

### Actions and Objectives

#### Exfiltration

##### Unusual Processes Manipulating Sensitive Data Files

```yaml
filemod:*.pst AND -process_name:outlook.exe
```

##### Processes accessing the Tor Network

```yaml
alliance_score_tor:*
```

##### Network Aware, Unsigned Applications on Sensitive Systems

```yaml
netconn_count:[1 TO *] AND -digsig_result:"Signed" AND (group:"<Domain Controllers>" OR group:"<Database Servers>")
```

#### Destruction

##### Processes Erasing the Master Boot Record

```yaml
cmdline:"fdisk /mbr"
```

##### Unsigned Processes Encrypting Files

```yaml
-digsig_result:"Signed" AND cmdline:"cipher"
```

##### CryptoLocker

```yaml
modload:rsaenh.dll AND process_name:*.exe AND filemod_count:[1000 TO *] AND path:AppData* AND regmod_count:[1 TO *] AND -process_name:chrome.exe AND -process_name:firefox.exe AND -process_name:iexplore.exe
```

#### Other

##### Processes accessing commonly open data ports

```yaml
ipport:20 OR ipport:21 OR ipport:22
```

## Github queries

### Binary

```yaml
    is_executable_image:"true"  digsig_result:"Unsigned"
```

```yaml
    is_executable_image:"true"  digsig_result:"Unsigned" observed_filename:c:\windows\temp\
```

```yaml
    is_executable_image:"true"  digsig_result:"Unsigned" observed_filename:\appdata\local\temp\
```

```yaml
    is_executable_image:"true"  digsig_result:"Unsigned" observed_filename:c:\windows\syswow64
```

```yaml
    (observed_filename:"c:\windows\system32\" OR observed_filename:"c:\windows\syswow64\") is_executable_image:"true" digsig_result:"Unsigned"
```

### Driver research

**URL To CbR**
```yaml
    /#/binaries/cb.urlver=1&q=observed_filename%3Ac%3A%5Cwindows%5Csystem32%5Cdrivers%5C&cb.q.digsig_result=(digsig_result%3A"Bad%20Signature"%20or%20digsig_result%3A"Invalid%20Signature"%20or%20digsig_result%3A"Invalid%20Chain"%20or%20digsig_result%3A"Untrusted%20Root"%20or%20digsig_result%3A"Explicit%20Distrust")&rows=10&start=0&sort=server_added_timestamp%20desc
```

```yaml
    observed_filename:c:\windows\system32\drivers\
```

```yaml
    observed_filename:c:\windows\system32\drivers\   digsig_result:"Explicit Distrust"
```

```yaml
    (observed_filename:"c:\windows\system32\" OR observed_filename:"c:\windows\syswow64\") .sys
```

```yaml
    (observed_filename:“c:\windows\syswow64\drivers”) .sys
```

```yaml
    (observed_filename:"c:\windows\system32\drivers\") .sys digsig_sign_time:[* TO 2015-10-01T23:59:59]
```

```yaml
    process_name:ntoskrnl.exe (digsig_result_modload:"Unsigned" OR digsig_result_modload:"Explicit\ Distrust")
```

```yaml
    process_name:spoolsv.exe -digsig_result_modload:Signed
```

### Process Search

```yaml
process_name:explorer.exe AND netconn_count:[500 TO *]
process_name:explorer.exe (modload:"c:\windows\syswow64\taskschd.dll")
```

### Behavior

```yaml
-digsig_result_filemod:Signed process_name:rundll32.exe
```

```yaml
process_name:cacls.exe cmdline:\startup\
```

```yaml
-digsig_result_parent:Signed process_name:svchost.exe
```

### DLL Hijack

c:\windows\system32\wbem\

```yaml
filemod:"wbem\loadperf.dll" OR filemod:"wbem\bcrypt.dll"
```

```yaml
process_name:svchost.exe cmdline:RemoteRegistry
```

```yaml
process_name:explorer.exe filemod:temp1_*.zip filemod:request*.doc
```

```yaml
process_name:winword.exe cmdline:request*.doc\"
```

```yaml
process_name:explorer.exe filemod:temp1_*.zip filemod:request*.doc
```

```yaml
process_name:mode.com
```

```yaml
digsig_result_parent:Unsigned process_name:raserver.exe
```

### scrobj load and behavior

```yaml
process_name:regsvr32.exe (modload:scrobj.dll) AND childproc_name:powershell.exe
```

```yaml
parent_name:powershell.exe AND process_name:nslookup.exe AND netconn_count:[1 TO *]
```

### Java Embedded MSI files

```yaml
process_name:java.exe cmdline:-classpath parent_name:javaw.exe (childproc_name:java.exe or childproc_name:conhost.exe)
process_name:java.exe cmdline:-classpath parent_name:javaw.exe (childproc_name:java.exe or childproc_name:conhost.exe) filemod:appdata\local\temp\*.class
```

[API](https://github.com/cparmn/CarbonBlackResponse/blob/master/msijar.py)


### UAC Bypass

[Reference](https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/)

```yaml
    regmod:"mscfile\shell\open\command"
```

```yaml
    parent_name:powershell.exe process_name:eventvwr.exe
```

### PPID Spoofing - Explorer CLSID

```yaml
    process_name:rundll32.exe cmdline:Shell32.dll*  cmdline:SHCreateLocalServerRunDll cmdline:{c08afd90-f2a1-11d1-8455-00a0c91f3880}
```

### PowerShell NSLookUp Spawn

[reference](https://ti.360.net/blog/articles/latest-target-attack-of-darkhydruns-group-against-middle-east-en/)

```yaml
    parent_name:powershell.exe process_name:nslookup.exe
```

### CSC spawns

```yaml
    (process_name:excel.exe OR process_name:winword.exe OR process_name:outlook.exe) childproc_name:csc.exe
```

```yaml
    (process_name:excel.exe OR process_name:winword.exe OR process_name:outlook.exe) filemod:.cs
```

```yaml
    parent_name:powershell.exe process_name:csc.exe
```

### Domain Enumeration

https://github.com/clr2of8/DPAT

```yaml
    process_name:ntdsutil.exe
```

```yaml
    process_name:dcdiag.exe
```

```yaml
    process_name:repadmin.exe
```

```yaml
    process_name:netdom.exe
```

```yaml
    company_name:"http://www.joeware.net"
```

### EternalBlue - Miner

[Reference](https://labsblog.f-secure.com/2019/01/03/nrsminer-updates-to-newer-version/)

```yaml
    parent_name:wininit.exe process_name:spoolsv.exe
```

```yaml
    process_name:sc.exe cmdline:Snmpstorsrv
```

```yaml
    process_name:svchost.exe digsig_result_modload:unsigned
```

### Eternalblue-Doublepulsar-Metasploit

- [reference](https://github.com/ElevenPaths/Eternalblue-Doublepulsar-Metasploit/tree/master/deps)
- [reference](https://gist.github.com/misterch0c/08829bc65b208609d455a9f4aeaa2a6c)


#### Filemod
```yaml
etebcore-2.x86.dll  
eternalblue-2.2.0.fb  
eternalchampion-2.0.0.fb
```

#### Modload
```yaml
trch-1.dll
libxml2.dll
tucl-1.dll
coli-0.dll
exma-1.dll
tibe-2.dll
cnli-1.dll
xdvl-0.dll
crli-0.dll
ssleay32.dll
libeay32.dll
trfo-2.dll
posh-0.dll
ucl.dll
zlib1.dll
```

### SQLi Dumper + spam

```yaml
    filemod:"url exploitables.xml"
```

```yaml
    filemod:"url list.txt"
```

```yaml
    process_name:"sqli dumper.exe"
```

```yaml
    process_name:"advanced mass sender.exe"
```

```yaml
    process_name:"turbomailer.exe"
```

```yaml
    modload:"appvirtdll64_advanced mass sender.dll"
```

```yaml
    process_name:storm.exe
```

### CobaltStrike - Argue

```yaml
    (modload:"c:\windows\syswow64\ntmarta.dll") process_name:svchost.exe
```

```yaml
    (modload:"c:\windows\system32\wshtcpip.dll") digsig_result:Unsigned (modload:"c:\windows\system32\wship6.dll")
```

```yaml
    (modload:"c:\windows\syswow64\iertutil.dll" modload:"c:\windows\syswow64\ntmarta.dll") process_name:rundll32.exe
```

```yaml
    (modload:"c:\windows\syswow64\iertutil.dll" modload:"c:\windows\syswow64\ntmarta.dll") process_name:rundll32.exe AND netconn_count:[1 TO * ]
```

```yaml
    digsig_result_parent:Unsigned (process_name:svchost.exe -username:SYSTEM -username:"NETWORK SERVICE" -username:"LOCAL SERVICE" -cmdline:"UnistackSvcGroup")
```

```yaml
    digsig_result_parent:Unsigned process_name:svchost.exe
```

```yaml
    parent_name:rundll32.exe process_name:svchost.exe
```

### Process

```yaml
    (regmod:"\registry\user\.default\software\microsoft\windows\currentversion\internet settings\proxyenable") digsig_result:Unsigned AND path:c:\windows\syswow64\*
```

```yaml
    process_name:procdump.exe cmdline:-accepteula
```

```yaml
    process_name:procdump.exe cmdline:lsass.exe
```

```yaml
    digsig_result_parent:Unsigned process_name:explorer.exe
```

```yaml
    process_name:schtasks.exe cmdline:/c
```

```yaml
    process_name:schtasks.exe cmdline:"cscript.exe"
```

```yaml
    process_name:schtasks.exe cmdline:"wscript.exe"
```

```yaml
    process_name:schtasks.exe cmdline:"powershell.exe"
```

```yaml
    crossproc_type:"remotethread" AND -process_name:wmiprvse.exe -process_name:svchost.exe -process_name:csrss.exe
```

#### klist

[Reference](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/klist)

```yaml
    process_name:klist.exe
```

#### dfsvc/browser broker queries

```yaml
    parent_name:browser_broker.exe process_name:mshta.exe
```

```yaml
    parent_name:browser_broker.exe process_name:rundll32.exe
```

```yaml
    process_name:dfsvc.exe digsig_result_child:"Unsigned" OR digsig_result_child:"Untrusted Root"
```

```yaml
    process_name:browser_broker.exe digsig_result_child:Unsigned
```

```yaml
    process_name:rundll32.exe childproc_name:dfsvc.exe
```

```yaml
    is_executable_image_filewrite:True -path:google\chrome\* and -path:google\update\* -digsig_result_filewrite:Signed filemod:local\settings\* filemod:appdata\local\temp\*
```

```yaml
    process_name:lsass.exe digsig_result_filewrite:"Unsigned"
```

```yaml
    process_name:lsass.exe AND digsig_result_modload:"Unsigned"
```

```yaml
    filemod:Content.Outlook\*  and is_executable_image_filewrite:True
```

```yaml
    filemod:Content.Outlook\*  and -digsig_result_filewrite:Signed
```

```yaml
    process_name:winlogon.exe AND netconn_count:[1 TO *]
```

```yaml
    filemod: “Start Menu\Programs\Startup”
```

```yaml
    regmod:CurrentVersion\Run*
```

```yaml
    filemod:windows\system32\* digsig_result:unsigned digsig_result_filewrite:"Unsigned"
```

```yaml
    regmod:services\national* digsig_result:unsigned
```

```yaml
    regmod:services\svchostc* digsig_result:unsigned
```

```yaml
    path:windows\system32\* digsig_result:unsigned parent_name:services.exe childproc_count:1
```

```yaml
    (regmod:"\registry\user\s-1-5-21-348440682-330175067-1304115618-242891\software\microsoft\office\14.0\excel\security\accessvbom")
```

```yaml
    (process_name:cmd.exe OR process_name:powershell.exe OR process_name:wmic.exe OR process_name:msbuild.exe OR process_name:mshta.exe OR process_name:wscript.exe OR process_name:cscript.exe OR process_name:installutil.exe OR process_name:rundll32.exe OR process_name:regsvr32.exe OR process_name:msxsl.exe OR process_name:regasm.exe OR process_name:regsvcs.exe) (domain:pastebin.com OR domain:dl.dropboxusercontent.com OR domain:githubusercontent.com)
```

```yaml
    digsig_result_child:"Unsigned" ((parent_name:chrome.exe OR parent_name:firefox.exe OR parent_name:iexplore.exe OR parent_name:microsoftedge.exe OR parent_name:outlook.exe) is_executable_image_filewrite:"true")
```

```yaml
    digsig_result_process:"Unsigned" ((parent_name:chrome.exe OR parent_name:firefox.exe OR parent_name:iexplore.exe OR parent_name:microsoftedge.exe OR parent_name:outlook.exe) is_executable_image_filewrite:"true")
```

```yaml
    regmod:"keyboard layout\2"
```

```yaml
    (regmod:"\registry\machine\software\microsoft\windows nt\currentversion\image file execution options\cmd.exe\verifierdlls")
```

```yaml
    process_name:mshta.exe modload:mscoree.dll
```

```yaml
    (modload:mscoree.dll AND modload:system.management.automation.dll) -process_name:powershell_ise.exe -process_name:sdiagnhost.exe -process_name:mscorsvw.exe -process_name:powershell.exe -process_name:searchfilterhost.exe
```

```yaml
    process_name:netsh.exe cmdline:appdata/
```

```yaml
    (modload:mscoree.dll AND modload:system.management.automation.dll AND modload:mscorlib*) -process_name:powershell_ise.exe -process_name:sdiagnhost.exe -process_name:mscorsvw.exe -process_name:powershell.exe -process_name:searchfilterhost.exe
```

```yaml
    (cmdline:/user: OR cmdline:/pwd: OR cmdline:/username: OR cmdline:/password:)
```

```yaml
    process_name:notepad.exe (modload:vaultcli.dll AND modload:samlib.dll)
```

```yaml
    parent_name:explorer.exe process_name:lsass.exe
```

```yaml
    process_name:netsh.exe cmdline:ProgramData/
```

```yaml
    process_name:csc.exe netconn_count:[1 TO *]
```

```yaml
    path:programdata\* -path:programdata\*\* -process_name:chgservice.exe -process_name:userprofilemigrationservice.exe -process_name:mm.exe -process_name:mmimage.exe
```

```yaml
    process_name:rundll32.exe domain:.ru AND netconn_count:[1 TO *]
```

```yaml
    (process_name:powershell.exe OR internal_name:powershell) (modload:samlib.dll OR modload:vaultcli.dll)
```

```yaml
    parent_name:spoolsv.exe (process_name:cmd.exe OR process_name:powershell.exe)
```

```yaml
    digsig_result:Unsigned ipport:443 modload:winsta.dll path:appdata/local/temp/*
```

#### PsExec variants

```yaml
(process_name:psexec.exe OR process_name:rexec.exe OR process_name:rcmd.exe OR process_name:xcmd.exe)
```

#### MSBuild

```yaml
process_name:msbuild.exe digsig_result_modload:Unsigned parent_name:cmd.exe
```

```yaml
process_name:msbuild.exe crossproc_name:notepad.exe
```

```yaml
process_name:msbuild.exe (parent_name:powershell.exe OR parent_name:cmd.exe)
```

```yaml
process_name:msbuild.exe AND crossproc_type:"remotethread"
```

```yaml
modload:http://microsoft.build.utilities.v4.0.ni.dll and modload:http://microsoft.build.framework.ni.dll
crossproc_type:remotethread
```

#### Rundll32, scrobj, clr

```yaml
process_name:rundll32.exe modload:amsi.dll
```

```yaml
process_name:rundll32.exe (modload:scrobj.dll OR modload:clr.dll)
```

```yaml
process_name:rundll32.exe (modload:scrobj.dll OR modload:clr.dll) -username:SYSTEM cmdline:advpack.dll
```

```yaml
process_name:rundll32.exe (modload:scrobj.dll OR modload:clr.dll)  cmdline:ieadvpack.dll
```

```yaml
process_name:rundll32.exe (modload:scrobj.dll OR modload:clr.dll)  cmdline:syssetup.dll
```

```yaml
process_name:cscript.exe (modload:scrobj.dll AND modload:clr.dll)
```

```yaml
parent_name:cmd.exe process_name:installutil.exe modload:clr.dll -username:SYSTEM
```

```yaml
process_name:installutil.exe modload:clr.dll -username:SYSTEM -cmdline:realtek
```

```yaml
parent_name:cmd.exe process_name:installutil.exe modload:clr.dll
```

```yaml
process_name:installutil.exe modload:clr.dll -username:SYSTEM cmdline:.dll
```

```yaml
process_name:installutil.exe cmdline:.dll -username:SYSTEM
```

```yaml
process_name:regsvr32.exe AND cmdline:f1 AND childproc_name:rundll32.exe AND childproc_count:[2 TO *]
```

#### Office

```yaml
process_name:excel.exe|winword.exe|powerpnt.exe (cmdline:.dll OR cmdline:.exe)
```

```yaml
process_name:control.exe
```

```yaml
process_name:winword.exe cmdline:http:\
```

```yaml
parent_name:winword.exe process_name:rundll32.exe netconn_count:[1 TO *]
```

```yaml
"C:\Windows\system32\rundll32.exe" Shell32.dll,Control_RunDLL c:\users\public\test2.dll
```

```yaml
modload:mscor* AND modload:clr.dll AND -process_name:mscorsvw.exe AND path:c:\users* AND modload:samlib.dll
```

```yaml
process_name:winword.exe regmod:software\microsoft\windows\currentversion\run\* modload:vbe*.dll
```

```yaml
parent_name:winword.exe regmod:software\microsoft\windows\currentversion\run\* childproc_name:winword.exe childproc_name:cmd.exe
```

```yaml
    parent_name:outlook.exe (process_name:iexplore.exe OR process_name:chrome.exe OR process_name:microsoftedge.exe OR process_name:firefox.exe)
```

### WScript

```yaml
internal_name:wscript.exe -process_name:wscript.exe
```

```yaml
parent_name:taskeng.exe internal_name:wscript.exe -process_name:wscript.exe
```

```yaml
path:AppData\Roaming\*
```

```yaml
internal_name:schtasks.exe -process_name:schtasks.exe
```

### Lateral movement using SSH or RDP

```yaml
-file_version:6.1.7601.24441 observed_filename:termdd.sys
```

```yaml
(process_name:mstsc.exe OR process_name:ssh.exe)
```

### Look for netcat and variants

```yaml
(process_name:netcat.exe OR process_name:ncat.exe OR cmdline:nc)
```

### Conhost

```yaml
childproc_name:conhost.exe
```

### Bloodhound

#### BloodHound detection - network

```yaml
    ipport:445 AND netconn_count:[150 TO *] AND -process_name:ntoskrnl.exe AND process_name:*
```

#### BloodHound detection - command line

```yaml
    cmdline:--ExcludeDC OR cmdline:LoggedOn OR cmdline:ObjectProps OR cmdline:GPOLocalGroup OR product_name:"SharpHound"
```

#### BloodHound detection - file modifications

```yaml
    filemod:sessions.csv OR filemod:acls.csv OR filemod:group_membership.csv OR filemod:local_admins.csv OR filemod:computer_props.csv OR filemod:user_props.csv
```

#### BloodHound detection - network pipe

```yaml
    filemod:\pipe\samr AND filemod:\pipe\lsarpc AND filemod:pipe\srvsvc
```

```yaml
    netconn_count:[100 TO *] AND ipport:445 AND (filemod:lsarpc OR filemod:samr OR filemod:srvsvc)
```

### Squiblytwo

```yaml
    (process_name:wmic.exe OR internal_name:wmic.exe) (cmdline:format:\ AND cmdline:os)
```

```yaml
    (process_name:wmic.exe OR internal_name:wmic.exe) (cmdline:format:\ AND cmdline:os) AND netconn_count:[1 TO *]
```

```yaml
    (process_name:wmic.exe OR internal_name:wmic.exe) netconn_count:[1 TO *]
```

```yaml
    process_name:wmic.exe (modload:jscript.dll OR modload:vbscript.dll)
```

### Rogue DC

```yaml
    process_name:svchost.exe AND cmdline:"-k netsvcs -p -s gpsvc" AND domain:* AND -(ipaddr:172.20.1.200 OR ipaddr:10.100.12.4 OR ipaddr:172.20.0.117 OR ipaddr:10.100.86.75 OR ipaddr:10.254.1.120 OR ipaddr:10.254.1.69 OR ipaddr:10.254.1.121)
```

```yaml
    process_name:svchost.exe AND cmdline:"-k netsvcs -p -s gpsvc" AND domain:* AND -host_type:"domain_controller"
```

### Coin Miner

```yaml
    digsig_result:"Unsigned" company_name:"Zhuhai Kingsoft Office Software Co.,Ltd"
```

```yaml
    parent_name:lsass.exe process_name:cmd.exe childproc_name:reg.exe
```

```yaml
    parent_name:lsass.exe process_name:cmd.exe childproc_name:schtasks.exe
```

```yaml
    process_name:net1.exe cmdline:"net1 user IISUSER_ACCOUNTXX /del"
```

```yaml
    process_name:lsass.exe digsig_result_filewrite:"Unsigned"
```

```yaml
    company_name:"TODO: <公司名>"
```

```yaml
    parent_name:conhost.exe digsig_result_parent:"Unsigned"
```

[FireIce - XMR](https://github.com/fireice-uk/xmr-stak)


```yaml
    filemod:xmrstak_opencl_backend.dll
    filemod:xmrstak_cuda_backend.dll
```

```yaml
observed_filename:c:\windows\debug\
observed_filename:c:\windows\inf\
observed_filename:c:\windows\web\
```

### Certificates

Research paper on signed malware in relation to WoSign and 2 others:
https://acmccs.github.io/papers/p1435-kimA.pdf


#### Wosign

```yaml
digsig_issuer:"WoSign Class 3 Code Signing CA"
```

```yaml
digsig_issuer:"WoSign Class 3 Code Signing CA" company_name:"Microsoft Corporation"
```

#### Others

```yaml
digsig_issuer:"VeriSign Class 3 Code Signing 2010 CA"
```

```yaml
digsig_subject:"CHENGDU YIWO Tech Development Co., Ltd."
```

```yaml
digsig_issuer:"Thawte Code Signing CA - G2"
```

```yaml
digsig_issuer:"thawte SHA256 Code Signing CA"
```

```yaml
digsig_issuer:"WoTrus Code Signing CA"
```

```yaml
digsig_issuer:"DigiCert EV Code Signing CA"
```

```yaml
digsig_issuer:WEXTSLGLZVJPTNNHZG
```

```yaml
digsig_issuer:BNNMZZPTPXHZOIVJJV
```

```yaml
digsig_issuer:PDMPEGXSJGYPPMYBYO
```

```yaml
digsig_issuer:XFAJAAJUQJATWBWBZP
```

### Malware

It's highly possible Emotet, Ryuk, Qakbot and Trickbot are mixed in here.

#### Trickbot

```yaml
(ipport:447 OR ipport:449) process_name:svchost.exe filemod:injectdll64_configs*
```

```yaml
filemod: c:\windows\temp\*.bat
```

Catches all the BAT's being written to \temp

#### OrangeWorm

```yaml
process_name:rundll32.exe cmdline:ControlTrace AND childproc_count:[2 TO *] AND regmod_count:[1 TO *]
```

```yaml
company_name:"Indiana Software Foundation"
```

```yaml
(observed_filename:"c:\windows\system32\" OR observed_filename:"c:\windows\syswow64\") is_executable_image:"true" digsig_result:"Unsigned"
```

#### Qakbot/Emotet/malware?

```yaml
process_name:explorer.exe filemod:.wpq
process_name:explorer.exe filemod:.wpl
process_name:explorer.exe filemod:.dll
process_name:explorer.exe filemod:.dat
```

```yaml
    parent_name:userinit.exe digsig_result_process:Unsigned
```

```yaml
process_name:explorer.exe filemod:bot_serv[1]
process_name:explorer.exe filemod:t3[1]
```

```yaml
process_name:schtasks.exe (cmdline:powershell.exe OR cmdline:$windowsupdate OR cmdline:.wpq OR cmdline:.wpl)
```

```yaml
company_name:"Borland Corporation"
```

```yaml
digsig_publisher:"RMBMS Limited"
digsig_publisher:"PROVERA LIMITED"
digsig_publisher:"Skotari Limited"
digsig_publisher:"IMRAN IT SERVICES LTD"
```

```yaml
is_executable_image:"true" digsig_result:Unsigned observed_filename:\AppData\Roaming\Microsoft\
```

```yaml
digsig_subject:"Skotari Limited"
```

```yaml
digsig_issuer:"Sectigo RSA Code Signing CA"
digsig_issuer:"COMODO RSA Code Signing CA"
```

```yaml
is_executable_image:"true"  digsig_result:"Unsigned" observed_filename:c$
```

```yaml
is_executable_image:"true"  digsig_result:"Unsigned" observed_filename:admin$
```

```yaml
is_executable_image:"true"  digsig_result:"Unsigned"
```

```yaml
is_executable_image:"true"  digsig_result:"Signed"
```

```yaml
cmdline:$windowsupdate*
```

```yaml
process_name:schtasks.exe cmdline:WEEKLY
```

```yaml
    digsig_publisher:"Evaila IT Ltd"
```

```yaml
    digsig_issuer:"COMODO RSA Code Signing CA"
```

```yaml
    process_name:wmiprvse.exe modload:c:\windows\temp\* digsig_result_modload:Unsigned
```

```yaml
    is_executable_image:"true"  digsig_result:"Unsigned" observed_filename:c:\programdata\
```

```yaml
    is_executable_image:"true"  digsig_result:"Unsigned" observed_filename:\appdata\roaming\
```

```yaml
    is_executable_image:"true" digsig_result:Unsigned observed_filename:\AppData\Roaming\Microsoft\
```

```yaml
    is_executable_image:"true"  digsig_result:"Unsigned" observed_filename:C:\Windows\SysWOW64\
```

```yaml
    is_executable_image:"true"  digsig_result:"Unsigned" observed_filename:C:\Windows\system32\
```

```yaml
    is_executable_image:"true"  digsig_result:"Unsigned" observed_filename:C:\Windows\
```

```yaml
    is_executable_image:"true"  digsig_result:"Unsigned" observed_filename:C:\Windows\temp
```

```yaml
    -parent_name:perccli64.exe -parent_name:kix32.exe -parent_name:activrelay.exe digsig_result_parent:"Unsigned"
```

```yaml
    digsig_result_parent:"Unsigned" digsig_result_process:"Unsigned" digsig_result_child:"Unsigned"
```

```yaml
    digsig_result:"Unsigned" filemod:c:\windows\syswow64\*
```

```yaml
    (modload:"c:\windows\system32\wow64cpu.dll") digsig_result_process:"Unsigned" digsig_result_parent:"Unsigned"
```

```yaml
    digsig_result:"Unsigned" filemod:c:\programdata\*
```

```yaml
    digsig_result_process:Unsigned parent_name:services.exe
```

```yaml
    parent_name:taskeng.exe digsig_result_process:Unsigned -process_name:currentdefsloader.exe -process_name:sqltasks.exe
```

```yaml
    (company_name:"Fatal Enterprice" OR company_name:"FastSpring Past" OR company_name:"Qualifacts Systems Plane" OR company_name:"WehwGWE.hWRGW" OR company_name:"Microsoft Co" OR company_name:"WMI" OR company_name:"SimVentions Hole" OR company_name:"Microsoft Corporatio" OR company_name:"Win Interactive LLC* Right" OR company_name:"PERCo-SC-610T/L" OR company_name:"Hekuriporuc Ltd." OR company_name:"Hikaham Ltd." OR company_name:"С Corporation" OR company_name:"Roni Enterprice" OR company_name:"Conoha.jp" OR company_name:"P.A.C. Nichols" OR company_name:"Server Service Core DLL" OR company_name:"NTLM Shared Functionality" OR company_name:"ImTOO Software Studio" OR company_name:"TeamViewer GmbH" OR company_name:"BST" OR company_name:"America Online, Inc.")
```

### Mimikatz

```yaml
    company_name:"gentilkiwi (Benjamin DELPY)"
```

```yaml
    internal_name:mimidrv
```

```yaml
    (modload:advapi32.dll AND modload:crypt32.dll AND modload:cryptdll.dll AND modload:gdi32.dll AND modload:imm32.dll AND modload:kernel32.dll AND modload:KernelBase.dll AND modload:msasn1.dll AND modload:msvcrt.dll AND modload:ntdll.dll AND modload:rpcrt4.dll AND modload:rsaenh.dll AND modload:samlib.dll AND modload:sechost.dll AND modload:secur32.dll AND modload:shell32.dll AND modload:shlwapi.dll AND modload:sspicli.dll AND modload:user32.dll AND modload:vaultcli.dll)
```

```yaml
    digsig_result:"Unsigned" modload:samlib.dll modload:advapi32.dll
```


```yaml
    (modload:advapi32.dll AND modload:crypt32.dll AND modload:cryptdll.dll AND modload:gdi32.dll AND modload:imm32.dll AND modload:kernel32.dll AND modload:KernelBase.dll AND modload:msasn1.dll AND modload:msvcrt.dll AND modload:ntdll.dll AND modload:rpcrt4.dll AND modload:rsaenh.dll AND modload:samlib.dll AND modload:sechost.dll AND modload:secur32.dll AND modload:shell32.dll AND modload:shlwapi.dll AND modload:sspicli.dll AND modload:user32.dll)
```

```yaml
    process_name:lsass.exe filemod:c:\windows\system32\mimilsa.log
```

### Random

```yaml
    company_name:“RW-Everything”
    internal_name:RwDrv.sys
    digsig_subject:“ChongKim Chan”
    digsig_sign_time:[* TO 2015-10-01T23:59:59]
```

### Misc.

```yaml
(regmod:"\registry\machine\software\microsoft\windows defender security center\notifications\disablenotifications")
```

```yaml
(regmod:"\registry\machine\software\policies\microsoft\windows defender\disableantispyware")
```

```yaml
is_executable_image_filewrite:true AND process_name:powershell.exe
```

```yaml
cmdline:--* AND netconn_count:[2 TO *] AND modload:"c:\windows\syswow64\bcrypt.dll" AND digsig_result:"Untrusted Root"
```

```yaml
    process_name:powershell.exe (filemod:c:\windows\temp\*)
```

```yaml
    process_name:powershell.exe ipport:445
```

```yaml
    process_name:powershell.exe AND netconn_count:[2 TO *] ipport:445
```

```yaml
    process_name:powershell.exe AND netconn_count:[2 TO *] (ipport:445 OR ipport:80 OR ipport:443 OR ipport:137 OR ipport:138 OR ipport:135 OR ipport:22)
```

```yaml
    (process_name:powershell.exe or process_name:powershell_ise.exe) AND netconn_count:[2 TO *] (ipport:445 OR ipport:80 OR ipport:443 OR ipport:137 OR ipport:138 OR ipport:135 OR ipport:22)
```

```yaml
    parent_name:explorer.exe process_name:mshta.exe (modload:jscript.dll OR modload:vbscript.dll) netconn_count:[1 TO *]
```

```yaml
    process_name:mshta.exe (modload:jscript.dll OR modload:vbscript.dll) netconn_count:[1 TO *]
```

```yaml
    process_name:php.exe childproc_name:cmd.exe
```

```yaml
    parent_name:php.exe process_name:cmd.exe
```

```yaml
    parent_name:php.exe process_name:cmd.exe digsig_result_child:"Unsigned"
```

```yaml
    (filemod:wwwroot\* or filemod:htdocs\*) and (filemod:.aspx or filemod:.jsp or filemod:.cfm or filemod:.asp or filemod:.php) AND host_type:"server"
```

```yaml
    domain:.ru -process_name:iexplore.exe OR -process_name:chrome.exe OR -process_name:microsoftedge.exe OR -process_name:microsoftedgecp.exe OR -process_name:firefox.exe OR -process_name:opera.exe digsig_result:Unsigned
```



```yaml

```
