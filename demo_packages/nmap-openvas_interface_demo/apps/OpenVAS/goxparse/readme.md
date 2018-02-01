#GOXParse (Glens OpenVAS XML Parser)#

GOXParse is a python script which parses OpenVAS/Greenbone Security Assistant XML scan reports into a simple delimited (eg CSV) format, with options to filter by host and/or min/max CVSS score.

GOXParse can also integrate an existing CSV file of known hosts/ports (such as that produced by Nmap & GNXParse [http://bitbucket.com/memoryresident/gnxtools](http://bitbucket.com/memoryresident/gnxtools) ). This may be useful to compare the results of a full OpenVAS vulnerability scan made from an unfirewalled location (eg inside the DMZ) with a basic nmap portscan made from outside the firewall in order to identify which vulnerable services are exposed.

GOXParse was created to provide similar functionality for OpenVAS as Yet Another Nessus Parser (YANP) [https://code.google.com/p/yet-another-nessus-parser/](https://code.google.com/p/yet-another-nessus-parser/)

### Usage: ###
```
$ ./goxparse.py --help
usage: goxparse.py filename.xml [OPTIONS]

Glens OpenVas XML Parser (goxparse)

positional arguments:
  file  File containing OpenVAS XML report

optional arguments:
  -h, --help				show this help message and exit
  -i, -ips  				Output unfiltered list of scanned ipv4 addresses
  -host [HOSTIP]			Host to generate a report for
  -cvssmin [CVSSMIN]		Minimum CVSS level to report
  -cvssmax [CVSSMAX]		Maximum CVSS level to report
  -threatlevel [THREAT] 	Threat Level to match, LOG/LOW/MEDIUM/HIGH/CRITICAL
  -matchfile [MATCHFILE]		.csv file from which to match open ports, in format HOSTIP,port1,port2,port3
  -v, --version 		show program's version number and exit

usage examples:
        goxparse.py ./scan.xml -ips
        goxparse.py ./scan.xml -host <HOSTIP>
        goxparse.py ./scan.xml -cvssmin 5 -cvssmax 8
        goxparse.py ./scan.xml -threatlevel HIGH
```


### Sample Output:###
#### Normal####
```
$ ./goxparse.py ../testdata/report1.xml -cvssmin 8
Threat,IP,CVSS,Service,Port,Protocol,OID,Name
High,192.168.32.7,10.0,x11,6000,tcp,1.3.6.1.4.1.25623.1.0.10407,X Server
High,192.168.32.99,10.0,unknown,41150,udp,1.3.6.1.4.1.25623.1.0.902725,Nfs-utils rpc.statd Multiple Remote Format String Vulnerabilities
High,192.168.32.127,9.0,ssh,22,tcp,1.3.6.1.4.1.25623.1.0.103239,SSH Brute Force Logins with default Credentials
High,192.168.32.130,9.3,http,80,tcp,1.3.6.1.4.1.25623.1.0.110182,PHP version smaller than 5.3.3
High,192.168.32.130,9.3,https,443,tcp,1.3.6.1.4.1.25623.1.0.110182,PHP version smaller than 5.3.3
High,192.168.32.132,10.0,nfs,2049,udp,1.3.6.1.4.1.25623.1.0.102014,NFS export
High,192.168.32.193,9.0,ssh,22,tcp,1.3.6.1.4.1.25623.1.0.103239,SSH Brute Force Logins with default Credentials
High,192.168.32.8,10.0,nfs,2049,udp,1.3.6.1.4.1.25623.1.0.102014,NFS export
```
#### CSV file + threatlevel filter####
```
$ ./goxparse.py ../testdata/report1.xml -matchfile ../testdata/csvfile.csv -threatlevel high
High,192.168.33.7,7.5,mysql,3306,tcp,yes,1.3.6.1.4.1.25623.1.0.803462,MySQL 'yaSSL' Buffer Overflow Vulnerability
High,192.168.33.7,6.0,mysql,3306,tcp,yes,1.3.6.1.4.1.25623.1.0.803480,MySQL Multiple Unspecified Vulnerabilities - 03
High,192.168.33.194,9.0,ssh,22,tcp,no,1.3.6.1.4.1.25623.1.0.103239,SSH Brute Force Logins with default Credentials
High,192.168.33.7,6.0,mysql,3306,tcp,yes,1.3.6.1.4.1.25623.1.0.803482,MySQL Information Schema Unspecified Vulnerability
High,192.168.33.7,6.0,mysql,3306,tcp,yes,1.3.6.1.4.1.25623.1.0.803484,MySQL Multiple Unspecified Vulnerabilities - 01
High,192.168.13.195,9.0,ssh,22,tcp,yes,1.3.6.1.4.1.25623.1.0.103239,SSH Brute Force Logins with default Credentials
High,192.168.13.195,9.3,mysql,3306,tcp,no,1.3.6.1.4.1.25623.1.0.100271,MySQL 5.x Unspecified Buffer Overflow Vulnerability
```

#CSV Filter file format:#

Format is: IP,port1,port2,port3,etc

eg:
```
$ cat ./csvfile.csv
192.168.5.5,1,2,3,4,5,80,8000
192.168.5.6,21,22,25,80,443,5000
```