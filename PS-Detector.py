import socket
import struct
import time
import threading

lock = threading.Lock()


def main():
    # creates a new raw socket for packet capture
    packets = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))

    connections = {}
    sus_sec = {}
    sus_min = {}
    sus_fiveMinutes = {}
    suspicious_connections = {}
    start_time = time.time()
    while True:
        ethernet_data, address = packets.recvfrom(65536)
        #print(ethernet_data)
        dest_mac, src_mac, ip_protocol, ip_data = ethernet_dissect(ethernet_data)

        #print('dest MAC = {0}, src MAC = {1}, protocol = {2}'.format(dest_mac, src_mac, ip_protocol))
        if ip_protocol == 8:    # ipv4 packet
            ip_protocol, src_ip, dest_ip, transport_data = ipv4_dissect(ip_data)

            if ip_protocol == 6:    # tcp packet
                #print("TCP Packet:")
                src_port, dest_port, application_data = tcp_dissect(transport_data)
                connection_info = (src_ip, dest_ip, dest_port)
                connection_time = time.time() - start_time

                if connection_info not in connections:
                    connections[connection_info] = connection_time

            '''
            elif ip_protocol == 17: # udp packet
                print("UDP Packet:")
                src_port, dest_port = udp_dissect(transport_data)
                #print('UDP Packet: source port:{0}, dest port:{1}'.format(src_port, dest_port))print('Source MAC:{0}, Dest MAC:{1}, Source IP:{2}, Dest IP:{3}, Protocol: {4}, Source Port:{5}, ')
                print('Source MAC={0}, Dest = {1}, \nSource IP = {2}, Dest IP = {3} \nSource Port = {4}, Dest Port = {5} '
                      '\nProtocol = {6}'.format(src_mac, dest_mac, src_ip, dest_ip, src_port, dest_port, ip_protocol))

            elif ip_protocol == 1:  # ICMP
                print("ICMP Packet:")
                type, code = icmp_dissect(transport_data)
                #print('ICMP Packet: type={0}, code={1}'.format(type, code))
                print('Source MAC = {0}, Dest MAC = {1} \nSource IP = {2}, Dest IP = {3} \nProtocol = {4} \nICMP Type = {5}, '
                      'ICMP Code = {6},'.format(src_mac, dest_mac, src_ip, dest_ip, ip_protocol, type, code))
            else:
                print('dest IP = {0}, source IP = {1}, IP Protocol = {2}'.format(dest_ip, src_ip, ip_protocol))
            '''

        # need to check connections dict for entries older than 5 minutes, using a separate thread
        five_minutes = time.time() - start_time
        remove_thread = threading.Thread(target = RemoveStaleEntries, args=(connections, five_minutes))
        remove_thread.start()
        remove_thread.join()

        current_time = time.time() - start_time

        one_second_thread = threading.Thread(target=fanout, args=(connections, sus_sec, current_time, 1, 5))
        one_second_thread.start()
        one_minute_thread = threading.Thread(target=fanout, args=(connections, sus_min, current_time, 60, 100))
        one_minute_thread.start()
        five_minutes_thread = threading.Thread(target=fanout, args=(connections, sus_fiveMinutes, current_time, 300, 300))
        five_minutes_thread.start()
        one_second_thread.join()
        one_minute_thread.join()
        five_minutes_thread.join()




def RemoveStaleEntries(connections, time):
    lock.acquire()
    stale_keys = {key:val for key, val in connections.items() if time - val > 300}
    for k in stale_keys:
        del connections[k]
    lock.release()


def fanout(connections, susConnections, currentTime, fanoutTime, thresholdRate):
    susConnections = {}

    for k, v in connections.items():
        if(v > currentTime - fanoutTime) and (v < currentTime):
            if(k[0] in susConnections):
                susConnections[k[0]] += 1
            else:
                susConnections[k[0]] = 1

    for k,v in susConnections.items():
        if(v > thresholdRate):
            print("-----------")
            print("Portscanner detected from source IP:{0}".format(str(k)))
            print("Avg fanout rate:{0}".format(str(float(susConnections[k]))))
            if fanoutTime == 1:
                print("Threshold is {0} per second.".format(str(thresholdRate)))
            if fanoutTime == 60:
                print("Threshold is {0} per minute.".format(str(thresholdRate)))
            if fanoutTime == 300:
                print("Threshold is {0} per 5 minutes.".format(str(thresholdRate)))


# Dissect packet into mac addresses and protocol
# return formatted mac addresses and protocol
def ethernet_dissect(ethernet_data):
    dest_mac, src_mac, protocol = struct.unpack('!6s6sH', ethernet_data[:14])
    # the ! indicates big/little endian. Then grabs 6 bytes, 6 bytes, and H means unsigned short(2 bytes)
    return mac_format(dest_mac), mac_format(src_mac), socket.htons(protocol), ethernet_data[14:]
    #return mac_format(dest_mac), mac_format(src_mac), protocol, ethernet_data[14:]

# Format mac address
def mac_format(mac):
    mac = map('{:02x}'.format, mac)
    return ':'.join(mac).upper()

# Dissects packet data
# Returns protocol, source and dest IP's, and IP data
def ipv4_dissect(ip_data):
    # ipv4 has various fields for the first 8 bytes, so we skip those with !9x
    # the next byte is protocol, followed by 4 bytes of source ip and 4 bytes of target ip
    ip_protocol, source_ip, target_ip = struct.unpack('!9x B 2x 4s 4s', ip_data[:20])
    return ip_protocol, ipv4_format(source_ip), ipv4_format(target_ip), ip_data[20:]

def ipv4_format(address):
    return '.'.join(map(str, address))

# Dissects TCP packet
# Returns source and dest ports, along with transport data
def tcp_dissect(transport_data):
    #source_port, dest_port = struct.unpack('!HH', transport_data[:4])
    # select the first 4 bytes for source and dest ports
    # then skip sequence and ack bytes to get size and control flags
    source_port, dest_port, size_and_flags = struct.unpack('!HH 8x H', transport_data[:14])
    offset = (size_and_flags >> 12) * 4 # tcp header could be up to 60 bytes, these bits show where the header/payload are in the packet
    return source_port, dest_port, transport_data[offset:]

# Dissects UDP packets
# returns source and dest ports
def udp_dissect(transport_data):
    # select first 4 bytes for source and dest ports
    source_port, dest_port = struct.unpack('!HH', transport_data[:4])
    return source_port, dest_port

# Dissects ICMP packets
# returns type and code
def icmp_dissect(transport_data):
    # ICMP packets have a byte of type, byte of code, 2 byte checksum, then variable field up to 128 bits
    type, code = struct.unpack('!BB', transport_data[:2])   # first byte is type, second is code
    return type, code

if __name__ == "__main__":
    main()