#!/usr/bin/python
# -*- coding: utf-8 -*-
#-----------------------------------------------------------------------------------------------------------
#Description: Ferramenta que efectua scans de forma a detectar máquinas susceptíveis a serem 
#             utilizadas para ataques de reflexão através de dns,snmp,ntp,chargen e ssdp.
#Version:1.0
#Author: Helder Miguel Fernandes <helder.fernandes@fccn.pt>
#ScriptName:reflection_scan.py
#Lib requirements: python-nmap
#software requirements: nmap, nmap scripts: upnp-info.nse,ntp-monlist.nse,dns-recursion.nse,snmp-sysdescr.nse
#------------------------------------------------------------------------------------------------------------


import nmap,sys


if len(sys.argv)==1:
   print "Usage:reflection_scan.py <target>"
   exit(-1)


nm=nmap.PortScanner()
nm.scan(hosts=sys.argv[1],arguments='-sU -T3 -PN -n -pU:19,53,123,161,1900 --script=upnp-info,ntp-monlist,dns-recursion,snmp-sysdescr')

hosts_report=[]
report={}

for a in nm.all_hosts():
    report={}
    report['Host']=a	
    for port in nm[a]['udp'].keys():
	if port==19:	
	   if nm[a]['udp'][port]['state']=='open':
	      report['chargen']=True
	   else:
	      report['chargen']=False

	if port==53:
	   if 'script' in nm[a]['udp'][port].keys():
	      if 'dns-recursion' in nm[a]['udp'][port]['script'].keys():
	         report['dns']=True
	      else:
		 report['dns']=False
	   else:
	      report['dns']=False

	if port==123:
	   if 'script' in nm[a]['udp'][port].keys(): 
	      if 'ntp-monlist' in nm[a]['udp'][port]['script'].keys():
		 report['ntp']=True
	      else:
		 report['ntp']=False
	   else:
	      report['ntp']=False
	if port==161:
	   if 'script' in nm[a]['udp'][port].keys():
	      if 'snmp-sysdescr' in nm[a]['udp'][port]['script'].keys():
	         report['snmp']=True
	      else:
		 report['snmp']=False
	   else:
	      report['snmp']=False

	if port==1900:
	   if 'script' in nm[a]['udp'][port].keys():
	      if 'upnp-info' in nm[a]['udp'][port]['script'].keys():
	   	 report['ssdp']=True
	      else:
		 report['ssdp']=False
	   else:
	      report['ssdp']=False

    hosts_report.append(report)
     			
for host in hosts_report:
    for key in host.keys():
	if host[key]==True:
           print host    
	

  
  



