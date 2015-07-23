#Description: This tool uses nmap to detect which hosts can be used to execute reflection attacks with dns,snmp,ntp,chargen and ssdp protocols. 


#Version:1.0
#Author: Helder Miguel Fernandes <helder.fernandes@fccn.pt>
#ScriptName:reflection_scan.py
#Lib requirements: python-nmap
#software requirements: nmap, nmap scripts: upnp-info.nse,ntp-monlist.nse,dns-recursion.nse,snmp-sysdescr.nse




Usage:sudo reflection_scanner.py xxx.xxx.xxx.xxx/xx

results:

{'ntp': False, 'snmp': True, 'Host': u'xxx.xxx.xxx.xxx', 'chargen': False, 'dns': False, 'ssdp': False}

{'ntp': False, 'snmp': False, 'Host': u'xxx.xxx.xxx.xxx', 'chargen': True, 'dns': False, 'ssdp': True}


