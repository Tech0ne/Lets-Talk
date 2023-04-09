#!/usr/bin/python3

from Crypto.Cipher import AES
from itertools import product
import subprocess
import threading
import netifaces
import readline
import requests
import hashlib
import getpass
import socket
import random
import shlex
import time
import sys
import os

PORT = 58008
NAME = "Guest_"+ ''.join([random.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(5)])
DELAY = 0
NO_SCAN = False
DO_SERVER = True
PASSWORD = None
TYPE = "LAN"

SRV = None

ACTIONS = ["scan ", "clear ", "scan-clear ", "quit ", "exit ", "hosts ", "connect ", "srv-start ", "add-host ", "requests ", "ban ", "infos ", "help ", "name "]
COMMANDS = ACTIONS[:]

REQUESTS = {}
BANNED = []

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
        string = f"{self.name:^20} : [{self.spaces}] {self.percent:.2f} %"
        string += ' ' * (os.get_terminal_size()[0] - len(string) - 1)
        print(string, end='\r')
    
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

class Server:
    def __init__(self, host="0.0.0.0"):
        self.host = host
        self.port = PORT
        if (TYPE == "LAN"):
            self.socker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            self.socker = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
        self.is_stoped = threading.Event()
    
    def run(self):
        try:
            self.socker.bind((self.host, self.port))
        except OSError:
            print("[-] Address already in use, or could not run bluetooth !")
            print(f"[+] Please kill the process using the port {self.port} and restart the server using the \"srv-start\" command")
            self.is_stoped.set()
            return
        self.socker.listen(5)
        while not self.is_stoped.is_set():
            conn, (ip, port) = self.socker.accept()
            if ip in BANNED:
                conn.close()
                continue
            comm = conn.recv(4096).decode()
            if comm.startswith("NAME"):
                conn.send(NAME.encode())
                conn.close()
            elif comm.startswith("CONN"):
                name = username(comm.split('\n')[1])
                print(f"\n[!] Got a connection request from \"{name}\" (\"{ip}\", on port {port}).")
                print("[+] Check requests using the \"requests\" command")
                print(">> ", end='')
                REQUESTS[(name, ip)] = conn

    def accept(self, name):
        conn = None
        for req, _conn in REQUESTS.items():
            if username(name) in req:
                conn = _conn
                break
        if not conn:
            print("[!] Could not retreive connection !")
            return
        conn.send(b"OK")
        threading.Thread(target=handle_recv, args=(conn, name)).start()
        try:
            while 1:
                conn.send(crypt(input().encode(), PASSWORD.encode()))
        except:
            print(f"[!] Closed connection with {name}")
    
    def start(self):
        threading.Thread(target=self.run, daemon=True).start()
    
    def stop(self):
        self.is_stoped.set()
        try:
            s = socket.socket()
            s.connect(("localhost", self.port))
            s.send(b"NULL")
            s.close()
        except:
            pass

def is_ip(ip: str):
    nbs = ip.split('.')
    if len(nbs) != 4:
        return False
    for nb in nbs:
        if not nb.isdigit():
            return False
        if int(nb) > 255 or int(nb) < 0:
            return False
    return True

def is_mac(mac: str):
    mac = mac.upper()
    nbs = mac.split(':')
    if len(nbs) != 6:
        return False
    for nb in nbs:
        if len(nb) != 2:
            return False
        if not (nb[0] in "0123456789ABCDEF" and nb[1] in "0123456789ABCDEF"):
            return False
    return True

def exit(ret = 0):
    print("\n[!] Exiting...")
    if SRV:
        SRV.stop()
    sys.exit(ret)

def usage():
    print(f"Usage : {sys.argv[0]} [-p|--port port] [-n|--name name] [-s|--scan-speed speed] [-t|--type] [--no-server] [--password] [--no-scan]")
    print("\t-p, --port       port      : Specify the listen and scan port")
    print("\t-n, --name       name      : Specify the name to use in the network")
    print("\t-s --scan-speed  speed     : Specify the delay for the scan (default is 0 second)")
    print("\t-t --type        type      : Specify connection type : LAN or BLUETOOTH")
    print("\t--no-server                : Do not start a listener (You won't appear online)")
    print("\t--password       password  : Specify the password to use (need to be the same for the both users)")
    print("\t--no-scan                  : Juste start the server and pop the shell, no scan (use the \"scan\" command to do it)")
    exit()

def clear():
    os.system("clear")

def complete(text, state):
    for cmd in COMMANDS:
        if cmd.startswith(text):
            if not state:
                return cmd
            else:
                state -= 1

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
    if not len(dic.keys()):
        print("Empty")
        return
    key_length = max([len(str(k)) for k in dic.keys()]) + 2
    val_length = max([len(str(v)) for v in dic.values()]) + 2
    print("+" + ("-" * key_length) + "+" + ("-" * val_length) + "+")
    for key, value in dic.items():
        print(f"|{str(key):^{key_length}}|{str(value):^{val_length}}|")
        print("+" + ("-" * key_length) + "+" + ("-" * val_length) + "+")
    print()

def to_type(n: str, _type: type):
    try:
        return _type(n)
    except:
        usage()

def username(name: str):
    final = ""
    for e in name:
        if e in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.":
            final += e
    return final

def update_configs():
    global PORT, NAME, DELAY, NO_SCAN, DO_SERVER, PASSWORD, TYPE
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
        if argv in ("-t", "--type"):
            if i < (len(sys.argv) - 1):
                i += 1
                if not sys.argv[i].upper() in ("LAN", "BLUETOOTH"):
                    usage()
                TYPE = sys.argv[i].upper()
                if PORT == 58008:
                    PORT = 4
            else:
                usage()
        if argv == "--no-server":
            DO_SERVER = False
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

def exec_command(command: str):
    try:
        p = subprocess.Popen(shlex.split(command), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
        if p.returncode != 0:
            return err.decode()
        return out.decode()
    except:
        return None

def get_main_ip():
    try:
        if TYPE == "LAN":
            return exec_command("hostname -I").split(' ')[0]
        else:
            return exec_command("hcitool dev").split('\t')[-1].split('\n')[0]
    except Exception:
        return None

def get_iface_name_from_ip(ip: str):
    if TYPE == "LAN":
        for iface in netifaces.interfaces():
            if not netifaces.ifaddresses(iface).get(2):
                continue
            if netifaces.ifaddresses(iface).get(2)[0].get('addr') == ip:
                return iface
        return None
    else:
        devices = exec_command("hcitool dev").split('\n')[1:]
        for device in devices:
            if device.split('\t')[-1] == ip:
                return device.split('\t')[1]
        return None

def get_netmask_from_iface(iface: str):
    if TYPE == "LAN":
        return netifaces.ifaddresses(iface)[2][0]['netmask']
    return None

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
        if not is_ip(target):
            return False
        s = socket.socket()
        s.settimeout(2)
        s.connect((target, PORT))
        s.send(b"NAME")
        name = s.recv(4096).decode()
        s.close()
        string = f"[+] Found a server at IP \"{target}\" : \"{username(name)}\""
        print((" " * (os.get_terminal_size()[0] - 1)) + "\r" + string)
        hosts[target] = username(name)
        return True
    except socket.error:
        hosts[target] = None
        return False

def start_scaners(t_list: list, hosts: dict, w: ProgressBar):
    for target in t_list:
        if w.do_stop.is_set():
            return
        threading.Thread(target=is_up,  args=(target, hosts)).start()
        time.sleep(DELAY)

def run_scan():
    global COMMANDS
    hosts = {}
    t_list = get_targets_list()
    random.shuffle(t_list)
    print("[+] Starting the scan")
    w = ProgressBar("Scanning...", os.get_terminal_size()[0] - 40, len(t_list))
    w.start()
    length = 0
    threading.Thread(target=start_scaners, args=(t_list, hosts, w)).start()
    try:
        while (length < len(t_list)):
            if len(hosts.keys()) > length:
                w.add()
                length += 1
    except KeyboardInterrupt:
        w.stop()
        return {}
    w.stop()
    keys = sorted(hosts)
    sorted_hosts = {}
    COMMANDS = ACTIONS[:]
    for key in keys:
        if hosts[key]:
            COMMANDS.append(hosts[key])
            COMMANDS.append(key)
            sorted_hosts[key] = hosts[key]
    if not sorted_hosts:
        print("[-] No target found\n")
        return {}
    print("[+] Scan done\n")
    print_dict(sorted_hosts)
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

def handle_recv(s: socket.socket, target: str):
    try:
        while 1:
            print(decrypt(s.recv(2 ** 14), PASSWORD.encode()).decode())
            s.send(b"")
    except:
        s.close()
        print(f"[-] Lost connection with {target} !")

def connect_to(name: str, hosts: dict):
    if TYPE == "LAN":
        if not is_ip(username(name)):
            for k, v in hosts.items():
                if username(v) == username(name):
                    name = k
                    break
            if not is_ip(username(name)):
                print(f"[-] {username(name)} could not be resolved !")
                return
        name = username(name)
    else:
        if not is_mac(name):
            for k, v in hosts.items():
                if username(v) == username(name):
                    name = k
                    break
            if not is_mac(name):
                print(f"[-] {name} could not be resolved !")
                return
    try:
        if TYPE == "LAN":
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
        s.connect((name, PORT))
        s.send(b"CONN\n" + NAME.encode())
        print("[+] Connection asked, waiting for response...")
        data = s.recv(2048).decode()
        if data == "OK":
            print("[+] Connection accepted")
            return s
        else:
            s.close()
            print("[-] Conection refused")
    except KeyboardInterrupt:
        s.close()
        print("[-] Connection interrupted")

def interpret_command(command: str, hosts: dict):
    global SRV, NAME
    command += ' '
    if command.startswith("scan "):
        if TYPE != "LAN":
            print("[!] Can not start bluetooth scan !")
            return
        scan = run_scan()
        if not len(scan.keys()):
            return
        for k, v in scan.items():
            hosts[k] = v
    elif command.startswith("clear "):
        clear()
    elif command.startswith("scan-clear "):
        keys = list(hosts.keys())
        for k in keys:
            del hosts[k]
    elif command.startswith("quit ") or command.startswith("exit "):
        exit(0)
    elif command.startswith("hosts "):
        print_dict(hosts)
    elif command.startswith("add-host "):
        if not is_up(username(command[9:]), hosts):
            print(f"[-] {username(command[9:])} is not up !")
            return
        COMMANDS.append(username(command[9:]))
        COMMANDS.append(hosts[username(command[9:])])
    elif command.startswith("ban "):
        print(f"[+] Banning {username(command[4:])}")
        BANNED.append(username(command[4:]))
        print(f"[+] {username(command[4:])} banned !")
    elif command.startswith("name "):
        NAME = username(command[5:])
        print(f"[+] Changed the name to \"{username(command[5:])}\" !")
    elif command.startswith("help "):
        print("Commands :")
        print("\t- scan           : Scan the current network to find connected devices, and retreive their name")
        print("\t- clear          : Clear the screen")
        print("\t- scan-clear     : Remove the previous scan from the \"known list\"")
        print("\t- quit | exit    : Safely exit")
        print("\t- hosts          : List the known hosts")
        print("\t- connect        : Connect to the provided host name / ip")
        print("\t- add-host       : Manualy add host to \"known list\"")
        print("\t- requests       : Shows up the conections requests")
        print("\t- name           : Set the username")
        print("\t- ban            : Ban a specific IP")
        print("\t- srv-start      : Start the server (if it was stoped / dod not start)")
        print("\t- infos          : Display some infos")
        print("\t- help           : Display this help message")
    elif command.startswith("srv-start "):
        if SRV is not None:
            SRV.stop()
        SRV = Server()
        SRV.start()
        time.sleep(1)
        print("[+] Restarted the server !")
    elif command.startswith("requests "):
        i = 1
        dico = {}
        for k in REQUESTS.keys():
            dico[i] = f"{k[1]}: {k[0]}"
            i += 1
        print_dict(dico)
        good = False
        while not good:
            try:
                choice = int(input("[?] Accept connection : "))
                if choice > 0 and choice <= len(dico.keys()):
                    good = True
            except KeyboardInterrupt:
                choice = None
                good = True
            except:
                pass
        if choice:
            i = 1
            name = None
            for k in dico.values():
                if i == choice:
                    name = k.split(': ')
                    break
                i += 1
            if name:
                SRV.accept(name[0])
        else:
            print()
    elif command.startswith("connect "):
        s = connect_to(command[8:], hosts)
        if s:
            try:
                threading.Thread(target=handle_recv, args=(s, command[8:])).start()
                while 1:
                    s.send(crypt(input().encode(), PASSWORD.encode()))
            except:
                s.close()
            print("[-] Connection closed !")
    elif command.startswith("infos "):
        print_dict({
            "Username": NAME,
            "Port": PORT,
            "IP": get_main_ip(),
            "Interface": get_iface_name_from_ip(get_main_ip()),
            "Password hash": f"{hashlib.md5(PASSWORD.encode()).hexdigest()[:10]}...",
            "Nb of requests": str(len(list(REQUESTS.keys()))),
            "Server": "Running" if (SRV and not SRV.is_stoped.is_set()) else "Offline",
        })
    else:
        if command.split(' ')[0]:
            print(f"{command.split(' ')[0]}: Command not found !")

class Waiter:
    def __init__(self, string):
        self.string     = string
        self.is_runing  = True
        self.thread     = threading.Thread(target=self.start_waiter, daemon=True)
        self.thread.start()
    
    def stop(self):
        self.is_runing  = False
        self.thread.join()

    def start_waiter(self):
        i = 0
        chars = "/-\\|"
        while self.is_runing:
            print(f"{self.string} [{chars[i]}]", end='\r', flush=True)
            time.sleep(0.1)
            i = (i + 1) % 4
        print(f"{self.string} [✓]")

def do_zip_update():
    r = requests.get("https://raw.githubusercontent.com/Tech0ne/Lets-Talk/main/code/main.py").text
    with open("/usr/bin/local_chat", 'r') as f:
        data = f.read()
    if data != r:
        try:
            with open("/usr/bin/local_chat", 'w+') as f:
                f.write(r)
        except OSError:
            print("An update is available !")
            print("Run again as root (using sudo) to update !")
            sys.exit(1)
        print("\nLets-talk is now updated !")
        print("Please restart to aply updates !")
        sys.exit(1)

w = Waiter("Updating, please wait...")

do_zip_update()

w.stop()


def main():
    global PORT, NAME, DELAY, NO_SCAN, PASSWORD, SRV
    do_zip_update()
    clear()
    update_configs()
    banner()
    readline.parse_and_bind("tab: complete")
    readline.set_completer(complete)
    try:
        if not PASSWORD:
            PASSWORD = getpass.getpass("[?] Password : ")
        print()
        print_dict({
            "Username": NAME,
            "Port": PORT,
            "IP": get_main_ip(),
            "Interface": get_iface_name_from_ip(get_main_ip()),
            "Password hash": f"{hashlib.md5(PASSWORD.encode()).hexdigest()[:10]}..."
        })
        print()
        hosts = {}
        if not NO_SCAN and TYPE == "LAN":
            hosts = run_scan()
        SRV = Server()
        SRV.start()
    except:
        exit(1)
    while 1:
        try:
            interpret_command(input(">> "), hosts)
        except KeyboardInterrupt:
            print()
        except EOFError:
            exit(1)

if __name__ == '__main__':
    main()