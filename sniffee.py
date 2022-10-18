from scapy.all import *
from scapy.layers.http import TCP, HTTPRequest, HTTPResponse
from scapy.layers.inet import IP
import sys
import argparse
from colorama import init, Fore
import pyfiglet as fig
from alive_progress import alive_bar
import random

# _COLOURS
init()
green = Fore.LIGHTGREEN_EX
red = Fore.LIGHTRED_EX
blue = Fore.LIGHTBLUE_EX
highlite = Fore.MAGENTA
title_color = Fore.LIGHTMAGENTA_EX
cyan = Fore.CYAN
yellow = Fore.LIGHTYELLOW_EX
reset = Fore.RESET


# _ANIMATION
def jeff():
    items = range(random.randrange(500, 1200))
    with alive_bar(len(items), bar="classic") as bar:
        for item in items:
            bar()


# _TITLE
title = (fig.figlet_format("s n i f f e e"))
print(yellow + title + reset)
print(f"                                        ~{cyan}*.*{red} SHY.BUG {cyan}*.*")

# _CLI ARGUMENTS
argparse = argparse.ArgumentParser(description=f"{red}THIS TOOL IS USED TO SNIFF DATA OVER THE LAN {reset}\n"
                                               f"THIS TOOL CAPTURES TRAFFIC FROM eth0 \n",
                                   usage=f"cmd:= {blue} python3 {sys.argv[0]} {highlite}--iface {blue}<interface type>{reset}\n")
argparse.add_argument("--iface", help=f"{blue} interface which you wanna sinff {reset}", required=True)

args = argparse.parse_args()
iface = args.iface


def sniff_packets(iface):
    if iface:
        sniff(prn=process, iface=iface, store=False)
    else:
        sniff(prn=process, store=False)


def process(packets):
    try:
        if packets.haslayer(TCP):
            src_ip = packets[IP].src
            dst_ip = packets[IP].dst
            src_port = packets[TCP].sport
            dst_port = packets[TCP].dport
            print(
                f"{yellow}[+]   {reset}    SOURCE_IP: {green}{src_ip} {reset}        SOURCE_PORT: {blue}{src_port}{reset}\n"
                f"     DESTINATION_IP: {green}{dst_ip}  {reset}  DESTINATION_PORT:{blue} {dst_port}{reset}")

    except:
        pass

    if packets.haslayer(HTTPRequest):
        link = packets[HTTPRequest].Host.decode() + packets[HTTPRequest].Path.decode()
        method = packets[HTTPRequest].Method.decode()
        print(blue + "url found:=" + cyan)
        jeff()
        print(f"{yellow}[*] {red}connecting to {highlite}{link}{red} using {highlite}{method} method{reset} \n\n")

        try:
            # _HTTP_REQ.
            if inp == 1:
                if packets.haslayer(HTTPRequest):
                    print(f"{blue}[+] HTTP_REQ found:= {reset}\t")
                    jeff()
                    print(f"\t{packets[HTTPRequest].show()} {reset}\n\n")
        except:
            pass
        # _RAW_DATA
        if inp == 3:
            if packets.haslayer(Raw):
                print(f"{blue}data found:= \n \t{red}[*] {yellow}{packets[Raw].load.decode()} {reset}\n")

    # _HTTP_RESPONSE
    if inp == 2:
        if packets.haslayer(HTTPResponse):
            print(f"{yellow}[+] {blue}HTTP_RESPONSE found:= {reset}\n\t")
            print(f"\t{packets[HTTPResponse].show()}{reset}\n")


print(f"{highlite}enter the type of data to sniff::\n{reset}"
      f"1.{green}sniff HTTP REQ.\n{reset}"
      f"2.{green}sniff HTTP RESPONSE.  \n{reset}"
      f"3.{green}sniff RAW DATA")
inp = int(input())
sniff_packets(iface)
