# John Pace
# Athul Satheesh
# Port scanner
# Finds open tcp and udp ports on a target IP

import socket
import time
#target=''      # in class we used a global variable for the scanning function,
                # I changed this to a variable passed to each function to avoid the global

def main():
    target = input("[+] Enter Target IP:")
    wait_time = float(input("[+] Enter wait time:"))

    # Rather than open a new socket for every scan function call, just make one socket here
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Scans all ports of the target machine
    # while true is to keep this running, even after scanning all ports, to measure the
    # 5 minute collection rate of the detector
    while True:
        for portNumber in range(1, 65535 ):
            if tcp_scanner(tcp_sock, target, portNumber):
                print('[*] Port', portNumber, '/tcp','is open')

            print("Waiting", wait_time, "seconds between scans...")
            time.sleep(wait_time)
            #if udp_scanner(target, portNumber):
            #    print('Port', portNumber, '/udp', 'is open')# Port scanner
# Finds open tcp and udp ports on a target IP

import socket
import time
#target=''      # in class we used a global variable for the scanning function,
                # I changed this to a variable passed to each function to avoid the global

def main():
    target = input("[+] Enter Target IP:")
    wait_time = float(input("[+] Enter wait time:"))

    # Rather than open a new socket for every scan function call, just make one socket here
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Scans all ports of the target machine
    # while true is to keep this running, even after scanning all ports, to measure the
    # 5 minute collection rate of the detector
    while True:
        for portNumber in range(1, 65535 ):
            if tcp_scanner(tcp_sock, target, portNumber):
                print('[*] Port', portNumber, '/tcp','is open')

            print("Waiting", wait_time, "seconds between scans...")
            time.sleep(wait_time)
            #if udp_scanner(target, portNumber):
            #    print('Port', portNumber, '/udp', 'is open')


def tcp_scanner(tcp_sock, target, port):
    try:
        #tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_sock.connect((target,port))         # attempt to establish a tcp connection
        tcp_sock.close()
        return True                             # return true if the port is open
    except:
        return False

def udp_scanner(target,port):
    try:
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # don't need to make a socket every time, could be done outside of the function
        udp_sock.settimeout(2)      # timeout needs to be at least 2 seconds to see if a response comes back
        udp_sock.sendto(bytes("NOTHING", "utf-8"),(target, port)) # sends udp packet to the ip/port of the target
        response, addr = udp_sock.recvfrom(1024) # if an ICMP message comes back, the port is closed/firewalled
        if response != None:
            return True
        return False
    except:
        print('No response from UDP port{}. Port may be open but not responding.'.format(port))

if __name__=="__main__":
    main()


def tcp_scanner(tcp_sock, target, port):
    try:
        #tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_sock.connect((target,port))         # attempt to establish a tcp connection
        tcp_sock.close()
        return True                             # return true if the port is open
    except:
        return False

def udp_scanner(target,port):
    try:
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # don't need to make a socket every time, could be done outside of the function
        udp_sock.settimeout(2)      # timeout needs to be at least 2 seconds to see if a response comes back
        udp_sock.sendto(bytes("NOTHING", "utf-8"),(target, port)) # sends udp packet to the ip/port of the target
        response, addr = udp_sock.recvfrom(1024) # if an ICMP message comes back, the port is closed/firewalled
        if response != None:
            return True
        return False
    except:
        print('No response from UDP port{}. Port may be open but not responding.'.format(port))

if __name__=="__main__":
    main()