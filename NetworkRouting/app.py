import logging
import socket
import time
import subprocess

from apps import App, action

logger = logging.getLogger("apps")        

@action
def log_traffic(logFromIP, protocol):
    print("logging:")
    ips = logFromIP.split(" ")
    for ip in ips:
        print(ip)
        args = ['iptables', '-A', 'INPUT', '-p', protocol, '-s', ip, '-j', 'LOG', '--log-prefix', 'INPUT:DROP:', '--log-level', '6']
        runCommand(args)

    return True

@action
def drop_traffic(dropFromIP, protocol):
    print("dropping:")
    ips = dropFromIP.split(" ")
    for ip in ips:
        print(ip)
        args = ['iptables', '-A', 'INPUT', '-p', protocol, '-s', ip, '-j', 'DROP']
        runCommand(args)
    
    return True


#@action
def redirect_traffic(dropFrom, redirectTo, protocol):
    args = ['echo', '"1"', '>', '/proc/sys/net/ipv4/ip_forward']
    runCommand(args)
    
    args = ['iptables', '-t', 'nat', '-A', 'PREROUTING', '-s', dropFrom, '-j', 'DNAT', '--to-destination', redirectTo]
    runCommand(args)
    
    # redirect ************** Not working, doesn't show up in IPTables or do anything
    args = ['iptables', '-t', 'nat', '-A', 'POSTROUTING', '-j', 'MASQUERADE']
    runCommand(args)
    
    #args = ['iptables', '-t', 'nat', '-A', 'PREROUTING', '-s', redirectFrom, '-j', 'DNAT', '--to-destination', redirectTo]
    #runCommand(args)
    
    # redirect ************** Not working, doesn't show up in IPTables or do anything
    #args = ['iptables', '-t', 'nat', '-A', 'POSTROUTING', '-j', 'MASQUERADE']
    #runCommand(args)
    
    return True


@action
def delete_iptable_drop_rule(dropFromIP, protocol):
    print("dropping:")
    ips = dropFromIP.split(" ")
    for ip in ips:
        args = ['iptables', '-D', 'INPUT', '-p', protocol, '-s', ip, '-j', 'DROP']
        runCommand(args)
    
    return True

@action
def delete_iptable_log_rule(logFromIP, protocol):
    print("logging:")
    ips = logFromIP.split(" ")
    for ip in ips:
        args = ['iptables', '-D', 'INPUT', '-p', protocol, '-s', ip, '-j', 'LOG', '--log-prefix', 'INPUT:DROP:', '--log-level', '6']
        runCommand(args)
    return True

    
    
def runCommand(args):
    print(args)
    p = subprocess.Popen(args)

    while p.poll() is None:
        if p.poll() is not None:     
            break
    
    return

#redirect_traffic('172.217.7.206', '2.2.2.2', 'icmp')
#drop_traffic('172.217.7.206', 'icmp')


