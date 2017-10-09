# coding=utf-8
import getopt
import socket
from struct import *
import datetime
import pcapy
import sys
from impacket.ImpactDecoder import EthDecoder, LinuxSLLDecoder

CATCH_MODE = False
PROMISC_MODE = False

out = open('output.txt', 'w')

def main(argv):
    try:
        cmd_opts = "pchn"  # packets, catch, help, promisc
        opts, args = getopt.getopt(argv[1:], cmd_opts)
        for opt in opts:
            global CATCH_MODE
            global PROMISC_MODE
            if opt[0] == '-p':
                CATCH_MODE = True
            if opt[0] == '-c':
                CATCH_MODE = False
            if opt[0] == '-n':
                PROMISC_MODE = True
            if opt[0] == '-h':
                print "-p - перехват пакетов \n" \
                      "-c - распознавание протоколов RPD \n" \
                      "-n - неразборчивый режим"
    except getopt.GetoptError:
        pass

    # list all devices
    devices = pcapy.findalldevs()
    print devices

    print "Доступные устройства:"
    for d in devices:
        print d

    dev = raw_input("Введите название устройства: ")

    print "Сканируемое устройство: " + dev

    cap = pcapy.open_live(dev, 65536 * 8, PROMISC_MODE, 0)

    # start sniffing packets
    while (1):
        (header, packet) = cap.next()
        parse_packet(packet)


# Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr(a):
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]), ord(a[1]), ord(a[2]), ord(a[3]), ord(a[4]), ord(a[5]))
    return b


# function to parse a packet
def parse_packet(packet):
    # init:
    # telnet 23, STD RDP 3389, Radmin 4899, Teamviewer 80 443 53, ammyy 443 1255 5931
    bad_ports = [23, 3389, 4899, 80, 443, 53, 1255, 5931]
    bad_words_data = ['teamviewer', 'rdp', 'RDP', 'viewer', 'TEAMVIEWER', 'radmin',
                      'ammyyadmin', 'ammyy', 'telnet']

    # parse ethernet header
    eth_length = 14

    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH', eth_header)
    # print 'UNPACKING RAW ETH_HEADER: ' + str(eth)   # unpacking

    eth_protocol = socket.ntohs(eth[2])
    # print 'Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(
    # packet[6:12]) + ' Protocol : ' + str(eth_protocol)

    # Parse IP packets, IP Protocol number = 8
    if eth_protocol == 8:
        # Parse IP header
        # take first 20 characters for the ip header
        ip_header = packet[eth_length:20 + eth_length]

        # now unpack them :)
        iph = unpack('!BBHHHBBH4s4s', ip_header)

        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF

        iph_length = ihl * 4

        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])
        if CATCH_MODE:
            s = 'Версия : ' + str(version) + ' Длинна IP заголовка : ' + str(ihl) + \
                  ' TTL : ' + str(ttl) + ' Протокол : ' + str(protocol) + ' Адресс отправения : ' + \
                  str(s_addr) + ' Адресс доставки : ' + str(d_addr) + '\n'
            out.write(s)
            print s

        # TCP protocol
        if protocol == 6:
            t = iph_length + eth_length
            tcp_header = packet[t:t + 20]

            tcph = unpack('!HHLLBBHHH', tcp_header)

            source_port = tcph[0]
            dest_port = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            doff_reserved = tcph[4]
            tcph_length = doff_reserved >> 4
            if CATCH_MODE:
                s = 'Протокол: TCP ' + 'Исходный порт : ' + str(source_port) + ' Порт назначения : ' + str(
                    dest_port) + ' Порядковый номер : ' + str(
                    sequence) + ' Подтверждение : ' + str(acknowledgement) + ' Длина TCP заголовка : ' + str(
                    tcph_length) + '\n'
                print s
                out.write(s)
            else:
                if dest_port in bad_ports:
                    s = 'Замечено подключение на порт ' + str(dest_port) + ' с адресса ' + str(s_addr) + '\n'
                    print s
                    out.write(s)

            h_size = eth_length + iph_length + tcph_length * 4
            data_size = len(packet) - h_size

            # get data from the packet
            data = packet[h_size:]
            decode_data = EthDecoder().decode(data).get_data_as_string()
            if CATCH_MODE:
                print decode_data
                out.write(decode_data + '\n')
            else:
                for item in bad_words_data:
                    if item in decode_data:
                        s = 'Замечено подключение с ключевым словом: ' + item + ' с адресса ' + str(s_addr) + '\n'
                        print s
                        out.write(s)

        # ICMP Packets
        elif protocol == 1:
            u = iph_length + eth_length
            icmph_length = 4
            icmp_header = packet[u:u + 4]

            icmph = unpack('!BBH', icmp_header)

            icmp_type = icmph[0]
            code = icmph[1]
            checksum = icmph[2]

            s = 'Протокол: ICMP ' + 'Тип : ' + str(icmp_type) + \
                  ' Код : ' + str(code) + ' Checksum : ' + str(checksum) + '\n'
            print s

            h_size = eth_length + iph_length + icmph_length
            data_size = len(packet) - h_size

            # get data from the packet
            data = packet[h_size:]
            s = 'Данные пакета : ' + data + '\n'
            print s
            out.write(s)

        # UDP packets
        elif protocol == 17:
            u = iph_length + eth_length
            udph_length = 8
            udp_header = packet[u:u + 8]

            udph = unpack('!HHHH', udp_header)

            source_port = udph[0]
            dest_port = udph[1]
            length = udph[2]
            checksum = udph[3]

            if CATCH_MODE:
                s = 'Протокол: UDP ' + 'Исходный порт : ' + \
                      str(source_port) + ' Порт назначения : ' + str(dest_port) + ' Длинна : ' + str(
                    length) + ' Checksum : ' + str(checksum) + '\n'
                print s
                out.write(s)
            else:
                if dest_port in bad_ports:
                    s = 'Замечено подключение на порт ' + str(dest_port) + ' с адресса ' + str(s_addr) + '\n'
                    print s
                    out.write(s)

            h_size = eth_length + iph_length + udph_length
            data_size = len(packet) - h_size

            data = packet[h_size:]

            if CATCH_MODE:
                s = 'Данные пакета : ' + data + '\n'
                print s
                out.write(s)
            else:
                for item in bad_words_data:
                    if item in data:
                        s = 'Замечено подключение с ключевым словом: ' + item + ' с адресса ' + str(s_addr) + '\n'
                        print s
                        out.write(s)


if __name__ == "__main__":
    main(sys.argv)
