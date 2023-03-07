from Crypto.Cipher import AES
from itertools import product
import threading
import netifaces
import socket
import random
import time
import sys
import os

PORT = 58008
NAME = "Guest_"+ ''.join([random.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(5)])
HOST = None
PASSWORD = None

class ProgressBar:
    def __init__(self, name, length, nb):
        self.name = name
        self.length = length
        self.nb = nb
        self.count = 0
        self.spaces = ">" + (" " * (length - 1))
        self.percent = 0
        self.do_stop = threading.Event()

    def print(self):
        print(f"{self.name:^20} : [{self.spaces}] {self.percent:.2f} %\r", end='')
    
    def add(self):
        self.count += 1
        self.percent = (self.count * 100) / self.nb
        nb = int(round((self.count * self.length) / self.nb, 0))
        if not nb:
            nb = 1
        self.spaces = "=" * (nb - 1) + ">" + (" " * (self.length - nb))

    def run(self):
        while not self.do_stop.is_set():
            self.print()
            time.sleep(1)
    
    def start(self):
        threading.Thread(target=self.run, daemon=True).start()
    
    def stop(self):
        self.do_stop.set()
        print(" " * len(f"{self.name:^20} : [{self.spaces}] {self.percent:.2f} %"), end='\r')

def exit(ret = 0):
    print("\n[!] Exiting...")
    sys.exit(ret)

def usage():
    print(f"Usage : {sys.argv[0]} [-p|--port port] [-n|--name name] [--host host] [-p|--password]")
    print("\t-p, --port  port      : Specify the listen and scan port")
    print("\t-n, --name  name      : Specify the name to use in the network")
    print("\t--host      host      : Specify the connection host (do not scan)")
    print("\t--password  password  : Specify the password to use (need to be the same for the both users)")
    exit()

def print_dict(dic: dict):
    key_length = max([len(str(k)) for k in dic.keys()]) + 2
    val_length = max([len(str(v)) for v in dic.values()]) + 2
    print("+" + ("-" * key_length) + "+" + ("-" * val_length) + "+")
    for key, value in dic.items():
        print(f"|{key:^{key_length}}|{value:^{val_length}}|")
        print("+" + ("-" * key_length) + "+" + ("-" * val_length) + "+")

def to_int(n):
    try:
        return int(n)
    except:
        usage()

def username(name: str):
    final = ""
    for e in name:
        if e in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-":
            final += e
    return final

def update_configs():
    global PORT, NAME, HOST, PASSWORD
    for i in range(len(sys.argv)):
        argv = sys.argv[i]
        if argv in ("-h", "--help"):
            usage()
        if argv in ("-p", "--port"):
            if i < (len(sys.argv) - 1):
                i += 1
                PORT = to_int(sys.argv[i])
            else:
                usage()
        if argv in ("-n", "--name"):
            if i < (len(sys.argv) - 1):
                i += 1
                NAME = username(sys.argv[i])
            else:
                usage()
        if argv == "--host":
            if i < (len(sys.argv) - 1):
                i += 1
                HOST = sys.argv[1]
            else:
                usage()
        if argv == "--password":
            if i < (len(sys.argv) - 1):
                i += 1
                PASSWORD = sys.argv[i]
            else:
                usage()

def get_main_ip():
    os.system("hostname -I > /tmp/command.txt")
    if not os.path.isfile("/tmp/command.txt"):
        return ""
    with open("/tmp/command.txt", 'r') as f:
        ip = f.read().split(' ')[0]
    os.remove("/tmp/command.txt")
    return ip

def get_iface_name_from_ip(ip: str):
    for iface in netifaces.interfaces():
        if not netifaces.ifaddresses(iface).get(2):
            continue
        if netifaces.ifaddresses(iface).get(2)[0].get('addr') == ip:
            return iface
    return None

def get_netmask_from_iface(iface: str):
    return netifaces.ifaddresses(iface)[2][0]['netmask']

def get_targets_list():
    liste = []
    ip = get_main_ip()
    mask = get_netmask_from_iface(get_iface_name_from_ip(ip))
    mask = mask.split('.')
    base = ""
    for i in range(4):
        if mask[i] != '0':
            base += ip.split(".")[i]
            base += '.'
    if not base.count('.'):
        return None
    for _ip in product(list([str(e) for e in range(1, 256)]), repeat=4 - base.count('.')):
        liste.append(base + '.'.join(_ip))
    return liste

def is_up(target: str):
    try:
        s = socket.socket()
        s.settimeout(0.5)
        s.connect((target, PORT))
        name = s.recv(4096).decode()
        s.close()
        string = f"[+] Found a server at IP {target} : \"{username(name)}\""
        print(" " * (os.get_terminal_size()[0] - 1), end='\r')
        print(string)
        return name
    except socket.error:
        return False

def run_scan():
    hosts = {}
    t_list = get_targets_list()
    random.shuffle(t_list)
    print("[+] Starting the scan")
    w = ProgressBar("Scanning...", 40, len(t_list))
    w.start()
    for target in t_list:
        name = is_up(target)
        if name:
            hosts[target] = name
        w.add()
    w.stop()
    if not hosts:
        print("[-] No target found")
        exit()
    print("[+] Scan done")
    print()
    keys = sorted(hosts)
    sorted_hosts = {}
    for key in keys:
        sorted_hosts[key] = hosts[key]
    return sorted_hosts

def main():
    update_configs()
    if not HOST:
        hosts = run_scan()
        dic = {}
        i = 1
        for k, v in hosts.items():
            dic[i] = f"{k} : {v}"
        print_dict(dic)
            

if __name__ == '__main__':
    main()