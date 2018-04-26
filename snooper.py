from scapy.layers.dot11 import *
import os


def get_iface():
    no = 1
    ifaces = os.listdir("/sys/class/net")
    for iface in ifaces:
        print "["+str(no)+"] "+iface
        no += 1
    choice = raw_input("Enter Wireless Interface to Use: ")
    return ifaces[int(choice)-1]


def in_monitor(iface):
    chk = os.popen("iwconfig " + iface + " | grep Monitor").read()
    if chk == "":
        return False
    else:
        return True


def set_monitor(op, iface):
    os.system("sudo ifconfig " + iface + " down")
    if op == 1:
        os.system("sudo iw dev "+iface+" set type monitor")
    elif op == 0:
        os.system("sudo iw dev "+iface+" set type managed")
    else:
        print "Invalid choice"
    os.system("sudo ifconfig " + iface + " up")
    return in_monitor(iface)


def monitor_mode(iface):
    is_monitor = in_monitor(iface)

    if is_monitor:
        print "[+] Monitor mode enabled on " + iface
    else:
        while not is_monitor:
            print "[x] Monitor mode not enabled on " + iface + "\n[+] Enabling Monitor mode"
            is_monitor = set_monitor(1, iface)
            if is_monitor:
                print "[+] Monitor mode enabled on " + iface
    conf.iface = iface


def clean_up(iface):
    print "[+] Cleaning up the goodness :("
    set_monitor(0, iface)
    exit()


def list_all(pkt):
    if pkt.haslayer(Dot11) and pkt.type == 2:
        try:
            if 'TCP' in pkt and 'IP' in pkt:
                wrpcap('tcp.pcap', pkt, append=True)
            elif 'UDP' in pkt and 'IP' in pkt and pkt[4]['UDP'].dport == 53:
                print "DNS"
                print str(pkt[4][IP].src)+" > "+str(pkt[4][IP].dst)
                print hexdump(pkt[4]['UDP']['Raw'].load)
                wrpcap('dns.pcap', pkt, append=True)
        except:
            print "error"


interface = get_iface()
monitor_mode(interface)
try:
    sniff(iface=interface, prn=list_all, filter="type Data")
except KeyboardInterrupt:
    clean_up(interface)
