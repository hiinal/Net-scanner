import scapy.all as scapy
import optparse
print('''
    
███╗░░██╗███████╗████████╗░██████╗░█████╗░░█████╗░███╗░░██╗███████╗██████╗░
████╗░██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗██╔══██╗████╗░██║██╔════╝██╔══██╗
██╔██╗██║█████╗░░░░░██║░░░╚█████╗░██║░░╚═╝███████║██╔██╗██║█████╗░░██████╔╝
██║╚████║██╔══╝░░░░░██║░░░░╚═══██╗██║░░██╗██╔══██║██║╚████║██╔══╝░░██╔══██╗
██║░╚███║███████╗░░░██║░░░██████╔╝╚█████╔╝██║░░██║██║░╚███║███████╗██║░░██║
╚═╝░░╚══╝╚══════╝░░░╚═╝░░░╚═════╝░░╚════╝░╚═╝░░╚═╝╚═╝░░╚══╝╚══════╝╚═╝░░╚═╝
      
      
''')
def get_arguments():
    parser=optparse.OptionParser()
    parser.add_options("-t","--target",dest="target",help="Target IP / IP range.")
    (options, arguments)=parser.parse_args()
    return options

def scan(ip):
    arp_req=scapy.ARP(pdst=ip)
    broadcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broadcast=broadcast/arp_req
    ans_list=scapy.srp(arp_req_broadcast,timeout=1, verbose=False)[0]
    
    print("IP\t\t\tMAC Address\n---------------------------------")
    clients_list=[]
    for element in ans_list:
        client_dict={"ip":element[1].psrc,"mac":element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list

def print_result(res_list):
    print("IP\t\tMAC Address\n----------------------------------")
    for clients in res_list:
        print(clients["ip"]+clients["mac"])

options=get_arguments()
scan_res=scan(options.target)
print_result(scan_res)