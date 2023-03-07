from Crypto.Cipher import AES
from itertools import product
import threading
import netifaces
import hashlib
import getpass
import socket
import random
import time
import sys
import os

PORT = 58008
NAME = "Guest_"+ ''.join([random.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(5)])
DELAY = 0.02
NO_SCAN = False
PASSWORD = None

BANNER_A = """    _/                                      _/        _/_/_/  _/                    _/      
   _/          _/_/      _/_/_/    _/_/_/  _/      _/        _/_/_/      _/_/_/  _/_/_/_/   
  _/        _/    _/  _/        _/    _/  _/      _/        _/    _/  _/    _/    _/        
 _/        _/    _/  _/        _/    _/  _/      _/        _/    _/  _/    _/    _/         
_/_/_/_/    _/_/      _/_/_/    _/_/_/  _/        _/_/_/  _/    _/    _/_/_/      _/_/      

"""

BANNER_B = """ _                     _   _____ _           _   
| |                   | | /  __ \ |         | |  
| |     ___   ___ __ _| | | /  \/ |__   __ _| |_ 
| |    / _ \ / __/ _` | | | |   | '_ \ / _` | __|
| |___| (_) | (_| (_| | | | \__/\ | | | (_| | |_ 
\_____/\___/ \___\__,_|_|  \____/_| |_|\__,_|\__|

"""

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
            time.sleep(0.1)
    
    def start(self):
        threading.Thread(target=self.run, daemon=True).start()
    
    def stop(self):
        self.do_stop.set()
        print(" " * len(f"{self.name:^20} : [{self.spaces}] {self.percent:.2f} %"), end='\r')

def exit(ret = 0):
    print("\n[!] Exiting...")
    sys.exit(ret)

def usage():
    print(f"Usage : {sys.argv[0]} [-p|--port port] [-n|--name name] [-s|--scan-speed speed] [--password] [--no-scan]")
    print("\t-p, --port       port      : Specify the listen and scan port")
    print("\t-n, --name       name      : Specify the name to use in the network")
    print("\t-s --scan-speed  speed     : Specify the delay for the scan (default is 0.02 second)")
    print("\t--password       password  : Specify the password to use (need to be the same for the both users)")
    print("\t--no-scan                  : Juste start the server and pop the shell, no scan (use the \"scan\" command to do it)")
    exit()

def clear():
    os.system("clear")

def banner():
    print()
    trm_size = os.get_terminal_size()[0]
    if ((trm_size - len(BANNER_B.split('\n')[0])) < 1):
        print("-" * 10 + "\nLocal Chat\n" + "-" * 10)
        return
    if ((trm_size - len(BANNER_A.split('\n')[0])) < 1):
        for e in BANNER_B.split('\n'):
            print(e.center(trm_size, ' '))
        return
    for e in BANNER_A.split('\n'):
        print(e.center(trm_size, ' '))

def print_dict(dic: dict):
    key_length = max([len(str(k)) for k in dic.keys()]) + 2
    val_length = max([len(str(v)) for v in dic.values()]) + 2
    print("+" + ("-" * key_length) + "+" + ("-" * val_length) + "+")
    for key, value in dic.items():
        print(f"|{key:^{key_length}}|{value:^{val_length}}|")
        print("+" + ("-" * key_length) + "+" + ("-" * val_length) + "+")

def to_type(n: str, _type: type):
    try:
        return _type(n)
    except:
        usage()

def username(name: str):
    final = ""
    for e in name:
        if e in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-":
            final += e
    return final

def update_configs():
    global PORT, NAME, DELAY, NO_SCAN, PASSWORD
    for i in range(len(sys.argv)):
        argv = sys.argv[i]
        if argv in ("-h", "--help"):
            usage()
        if argv in ("-p", "--port"):
            if i < (len(sys.argv) - 1):
                i += 1
                PORT = to_type(sys.argv[i], int)
            else:
                usage()
        if argv in ("-n", "--name"):
            if i < (len(sys.argv) - 1):
                i += 1
                NAME = username(sys.argv[i])
            else:
                usage()
        if argv in ("-s", "--scan-speed"):
            if i < (len(sys.argv) - 1):
                i += 1
                DELAY = to_type(sys.argv[i], float)
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
        if argv == "--no-scan":
            NO_SCAN = True

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

def is_up(target: str, hosts: dict):
    try:
        s = socket.socket()
        s.settimeout(5)
        s.connect((target, PORT))
        s.send(b"NAME")
        name = s.recv(4096).decode()
        s.close()
        string = f"[+] Found a server at IP {target} : \"{username(name)}\""
        print((" " * (os.get_terminal_size()[0] - 1)) + "\r" + string)
        hosts[target] = name
    except socket.error:
        hosts[target] = None

def start_scaners(t_list: list, hosts: dict):
    for target in t_list:
        threading.Thread(target=is_up,  args=(target, hosts)).start()
        time.sleep(DELAY)

def run_scan():
    hosts = {}
    t_list = get_targets_list()
    random.shuffle(t_list)
    print("[+] Starting the scan")
    w = ProgressBar("Scanning...", os.get_terminal_size()[0] - 40, len(t_list))
    w.start()
    length = 0
    threading.Thread(target=start_scaners, args=(t_list, hosts)).start()
    while (length < len(t_list)):
        if len(hosts.keys()) > length:
            w.add()
            length += 1
    w.stop()
    keys = sorted(hosts)
    sorted_hosts = {}
    for key in keys:
        if hosts[key]:
            sorted_hosts[key] = hosts[key]
    if not sorted_hosts:
        print("[-] No target found")
        exit()
    print("[+] Scan done")
    print()
    return sorted_hosts

def crypt(data: bytes, key: bytes):
    k = hashlib.md5(key).hexdigest().encode()
    cipher = AES.new(k, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return b''.join((cipher.nonce, tag, ciphertext))

def decrypt(data: bytes, key: bytes):
    k = hashlib.md5(key).hexdigest().encode()
    if (len(data) < 33):
        return None
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(k, AES.MODE_EAX, nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def connect_to(ip):
    pass

def main():
    global PORT, NAME, DELAY, NO_SCAN, PASSWORD
    clear()
    update_configs()
    banner()
    if not PASSWORD:
        PASSWORD = getpass.getpass("[?] Password : ")
    hosts = []
    if not NO_SCAN:
        hosts = run_scan()
        
            

if __name__ == '__main__':
    main()