from scapy.all import *
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
            if 'TCP' in pkt and 'IP' in pkt and 'Raw' in pkt:
                if pkt[4]['TCP'].dport == 80:
                    wrpcap('http.pcap', pkt, append=True)

                    data = get_data('http',pkt[4]['TCP'][Raw].load)
                    print "================ HTTP Request ================"
                    print "Source MAC: "+pkt[1].addr2
                    print "IP: "+str(pkt[4][IP].src)+" > "+str(pkt[4][IP].dst)
                    for field in data.keys():
                        #print field+": "+data[field]
                        if data[field] == 'POST':
                            print pkt.show()

                wrpcap('tcp.pcap', pkt)
            elif 'UDP' in pkt and 'IP' in pkt and pkt[4]['UDP'].dport == 53:
                #print "DNS"
                #print str("MAC: "+pkt[1].addr2+" IP: "+pkt[4][IP].src)+" > "+str(pkt[4][IP].dst)
                wrpcap('dns.pcap', pkt)
                #print "Query: "+get_data('dns')
        except Exception as e:
            print e


def get_data(proto, data=None):
    if proto == 'dns':
        packets = rdpcap('dns.pcap')
        for p in packets:
            if p.haslayer(DNS):
                return p[DNS].qd.qname

    elif proto == 'http':
        dict = {}
        lines = data.split('\n')
        for line in lines:
            if 'Host' in line:
                dict['host'] = line.split(': ')[1]
            elif 'GET' in line:
                dict['req'] = 'GET'
                #dict['requrl'] = dict['host'] + line.split( )[1]
            elif 'POST' in line:
                dict['req'] = 'POST'
                #dict['requrl'] = dict['host'] + line.split( )[1]
                print data
            elif 'Referer' in line:
                dict['ref'] = line.split(': ')[1]
            elif 'User' in line:
                dict['uagent'] = line.split(': ')[1]
        return dict


interface = get_iface()
monitor_mode(interface)
try:
    sniff(iface=interface, prn=list_all, filter="type Data")
except KeyboardInterrupt:
    clean_up(interface)
