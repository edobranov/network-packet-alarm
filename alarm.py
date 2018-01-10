# Filename: alarm.py
# Author:   Evgeni Dobranov
# Date:     10/25/2017
# Purpose:  CL tool for detecting the following criteria:
#           1. NULL scan
#           2. FIN scan
#           3. XMAS scan
#           4. Usernames and passwords sent in-the-clear (HTTP, FTP, IMAP, POP)
#           5. Nikto scan


import sys
from scapy.all import *


# scan types/flags (source: https://danielmiessler.com/study/tcpflags/)
NULL  = 0x00
FIN   = 0x01
SYN   = 0x02
RST   = 0x04
PSH   = 0x08
ACK   = 0x10
URG   = 0x20
XMAS  = FIN | PSH | URG
NIKTO = lambda payload : 'nikto' in payload or 'Nikto' in payload or \
                         'NIKTO' in payload


# protocol ports (source: http://www.networksorcery.com/enp/protocol/ip/ports00000.htm)
HTTP = lambda protocol : protocol in {80}
FTP  = lambda protocol : protocol in {20, 21}
IMAP = lambda protocol : protocol in {143, 220}
POP  = lambda protocol : protocol in {109, 110}


# a couple general vulnerable username/password phrases
HTTPKEY  = 'Authorization: Basic'
USERKEY1 = 'USER'
PASSKEY1 = 'PASS'
USERKEY2 = 'username='
PASSKEY2 = 'password='
EMAILKEY = 'LOGIN'


# alert # for command line printing
globalAlertID = 0


# parse options and values from command line
def main():

    if len(sys.argv) == 1:
        processInterface('eth0')

    elif len(sys.argv) == 2:
        if sys.argv[1] == '-h' or sys.argv[1] == '--help':
            printHelpMenu(True);
        else:
            printHelpMenu(False)

    elif len(sys.argv) == 3:
        if sys.argv[1] == '-i':
            processInterface(sys.argv[2])
        elif sys.argv[1] == '-r':
            processPcapFile(sys.argv[2])
        else:
            printHelpMenu(False)

    else:
        printHelpMenu(False)


# print help or error message to command line
def printHelpMenu(menu):

    if menu:
        print ('\n+-------------------------------------------------------------------+\n'
               '| alarm.py: A network sniffer that identifies basic vulnerabilities |\n'
               '+-------------------------------------------------------------------+\n\n'
               'usage: alarm.py [-h] [-i <INTERFACE>] [-r <PCAPFILE>]\n\n'
               'optional arguments:\n'
               '  -h, --help      show this help message and exit\n'
               '  -i <INTERFACE>  a network interface to sniff (default is eth0\n'
               '  -r <PCAPFILE>   a .pcap file to read\n')
    else:
        print ('Command not recognized. Try \'python ' + 
               sys.argv[0] + ' -h\' to see available options.')


# sniff specified network interface and identify vulnerabilities
def processInterface(iFace):

    print ('Sniffing interface ' + iFace + ' (^C to quit at any time)...')
    sniff(iface = iFace, prn = processPacket)


# parse specified pcap file and identify vulnerabilities
def processPcapFile(pcap):

    print ('Reading file ' + pcap + '...')
    packets = rdpcap(pcap)
    for p in packets:
        processPacket(p)


# check criteria for NULL, FIN, XMAS, Nikto scans and username-passwords sent in clear
def processPacket(p):

    if p.haslayer(TCP):

        if p[TCP].flags == NULL:
            printIncident('NULL scan is detected', getIP(p), 'TCP', None)
        
        elif p[TCP].flags == FIN:
            printIncident('FIN scan is detected', getIP(p), 'TCP', None)

        elif p[TCP].flags == XMAS:
            printIncident('XMAS scan is detected', getIP(p), 'TCP', None)

        analyzeNiktoScan(p)
        analyzePasswords(p)


# check for nikto scan
def analyzeNiktoScan(p):
    if p.haslayer(TCP):

        if p.haslayer(Raw):
            regularLoad = p[Raw].load
        else:
            return

        if NIKTO(str(p)):
            printIncident('Nikto scan is detected', getIP(p), 'TCP', None)


# check given packet for multiple ways that a password can be sent in the clear
def analyzePasswords(p):

    pSrc = p[TCP].sport  # source port of packet
    pDst = p[TCP].dport  # destination port of packet

    # get body of packet
    if p.haslayer(Raw):
        regularLoad = p[Raw].load
    else:
        return

    # sent/received from HTTP port
    if HTTP(pSrc) or HTTP(pDst):
        for line in regularLoad.split('\n'):

            # check for regular authorization header and decode password
            if HTTPKEY in line:
                userpass = line[len(HTTPKEY):]
                try:
                    userpass = userpass.decode('base64')
                except:
                    userpass = userpass

                printIncident('Username and password sent in-the-clear', getIP(p), 'TCP - HTTP', userpass)
                break

            # check an alternative method (query-like parameter)
            elif USERKEY2 in line and PASSKEY2 in line:
                printIncident('Username sent in-the-clear', getIP(p), 'TCP - HTTP',
                    line.split('&')[0][len(USERKEY2):])
                printIncident('Password sent in-the-clear', getIP(p), 'TCP - HTTP',
                    line.split('&')[1][len(PASSKEY2):])

    # sent/received from FTP port
    elif FTP(pSrc) or FTP(pDst):
        if USERKEY1 in regularLoad:
            printIncident('Username sent in-the-clear', getIP(p), 'TCP - FTP',
                regularLoad[len(USERKEY1)+1:].rstrip())
        if PASSKEY1 in regularLoad:
            printIncident('Password sent in-the-clear', getIP(p), 'TCP - FTP',
                regularLoad[len(PASSKEY1)+1:].rstrip())

    # sent/received from IMAP, POP ports
    elif IMAP(pSrc) or IMAP(pDst) or POP(pSrc) or POP(pDst):
        if EMAILKEY in regularLoad and '@' in regularLoad:
            line = regularLoad.split(' ')
            for l in range(len(line)):
                if l == len(line) - 2:
                    printIncident('Username sent in-the-clear', getIP(p), 'TCP - IMAP/POP',
                        line[l].rstrip())
                if l == len(line) - 1:
                    printIncident('Password sent in-the-clear', getIP(p), 'TCP - IMAP/POP',
                        line[l].rstrip())


# print result of incident formatted by caller
def printIncident(scanDesc, pIP, pProto, pBody):

    global globalAlertID  # needed to modify global value
    globalAlertID += 1

    # if there is additional content to print
    if pBody:
        print('ALERT #%d: %s from %s (%s) (%s)!' %
             (globalAlertID, scanDesc, pIP, pProto, pBody))
    else:
        print('ALERT #%d: %s from %s (%s)!' %
             (globalAlertID, scanDesc, pIP, pProto))


# return source ip of packet
def getIP(p):

    if p.haslayer(IP):
        return p[IP].src
    else:
        return '<no IP found>'


if __name__ == '__main__' : main()