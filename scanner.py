# scanner.py
import nmap
import json

def load_config(filename):
    with open(filename, 'r') as file:
        config = json.load(file)
    return config

def scan_network(target):
    nm = nmap.PortScanner()
    nm.scan(target)
    hosts = nm.all_hosts()
    return hosts, nm
