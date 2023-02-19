import socket
import struct
import textwrap

TAB1 = '\t'
TAB2 = '\t\t'
TAB3 = '\t\t\t'


def EthernetFrame(rawData):
    destinationAddress, sourceAddress, protocol = struct.unpack(
        '! 6s 6s H', rawData[:14])
    return MacAddress(destinationAddress), MacAddress(sourceAddress), socket.htons(protocol), rawData[14:]


def IPv4Packet(rawData):
    versionHeaderLength = rawData[0]
    version = versionHeaderLength >> 4
    headerLength = (versionHeaderLength & 15) * 4
    TTL, protocol, sourceAddress, destinationAddress = struct.unpack(
        '! 8x B B 2x 4s 4s', data[:20])
    return version, headerLength, TTL, protocol, IPv4Address(sourceAddress), IPv4Address(destinationAddress), data[headerLength]


def ICMPPacket(rawData):
    ICMPType, code, checkSum = struct.unpack('! B B H', rawData[:4])
    return ICMPType, code, checkSum, rawData[:4]


def TCPSegment(rawData):
    (sourcePort, destinationPort, sequence, ackowledgement,
     offsetReverseFlag) = struct.unpack('! H H L L H', rawData[:14])
    offset = (offsetReverseFlag >> 12) * 4
    finFlag = offsetReverseFlag & 1
    synFlag = (offsetReverseFlag & 2) >> 1
    rstFlag = (offsetReverseFlag & 4) >> 2
    pshFlag = (offsetReverseFlag & 8) >> 3
    ackFlag = (offsetReverseFlag & 16) >> 4
    urgFlag = (offsetReverseFlag & 32) >> 5
    return sourcePort, destinationPort, sequence, ackowledgement, finFlag, synFlag, rstFlag, pshFlag, ackFlag, urgFlag, rawData[offset:]


def UDPSegment(rawData):
    sourcePort, destinationPort, size = struct.unpack(
        '! H H 2x H', rawData[:8])
    return sourcePort, destinationPort, size, rawData[:8]


def IPv4Address(byteAddress):
    return '.'.join(map(str, byteAddress))


def MacAddress(byteAddress):
    return ':'.join(map('{:02x}'.format, byteAddress)).upper()


def lineFormatter(prefix, string, size=80):
    size -= len(prefix)
    if not isinstance(string, (str, bytes)):
        raise TypeError("'string' argument must be a string or a bytes object")
    if isinstance(string, bytes):
        string = ''.join('{:02x}'.format(byte) for byte in string)
    decodedString = ""
    for i in range(0, len(string), 2):
        hex_pair = string[i:i + 2]
        try:
            char = bytes.fromhex(hex_pair).decode('utf-8')
            decodedString += char
        except:
            decodedString += "-"
    return '\n'.join([prefix + line for line in textwrap.wrap(decodedString, size)])


Socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

while True:
    rawData, address = Socket.recvfrom(65536)
    destinationAddress, sourceAddress, protocol, data = EthernetFrame(rawData)

    # Ethernet Frame
    print("\n---------------------------------| Ethernet Frame: |---------------------------------")
    print("\t  | Destination: {}  | Source: {}  |".format(
        destinationAddress, sourceAddress))
    print("\t  |_________________________________|____________________________|\n")

    # IPv4 Packet
    if protocol == 8:
        (version, headerLength, TTL, protocol, sourceAddress,
         destinationAddress, data) = IPv4Packet(rawData)
        print("\t\t   IPv4 Packet\n")
        print("\t\t      Version: {} \n\t\t      Header Length: {} \n\t\t      Time to Live: {}\n".format(
            version, headerLength, TTL))

    # ICMP Packet
    if protocol == 1:
        ICMPType, code, checksum, data = ICMPPacket(rawData)
        print("\t\t   ICMP Packet\n")
        print("\t\t      Type: {} \n\t\t      Code: {} \n\t\t      Checksum: {}\n".format(
            ICMPType, code, checksum))
        print("\t\t      Data:\n")
        print(lineFormatter("\t\t      ", data))

    # TCP Segment
    if protocol == 6:
        (sourcePort, destinationPort, sequence, ackowledgement, finFlag,
         synFlag, rstFlag, pshFlag, ackFlag, urgFlag, data) = TCPSegment(rawData)
        print("\t\t   TCP Segment\n")
        print("\t\t      Source Port: {} \n\t\t      Destination Port: {}".format(
            sourcePort, destinationPort))
        print("\t\t      Sequence: {} \n\t\t      Acknowledge: {}\n".format(
            sequence, ackowledgement))
        print("\t\t      FLAG\n")
        print("\t\t         URG: {} \n\t\t         ACK: {} \n\t\t         PSH: {} \n\t\t         RST: {} \n\t\t         SYN: {} \n\t\t         FIN: {}\n".format(
            urgFlag, ackFlag, pshFlag, rstFlag, synFlag, finFlag))
        print("\t\t      Data:\n")
        print(lineFormatter("\t\t      ", data))

    # UDP Segment
    if protocol == 17:
        sourcePort, destinationPort, length, data = UDPSegment(rawData)
        print("\t\t   UDP Segment\n")
        print("\t\t      Source Port: {} \n\t\t      Destination Port: {} \n\t\t      Length: {}\n".format(
            sourcePort, destinationPort, length))

    # Other Data
    if protocol != 17 and protocol != 6 and protocol != 8 and protocol != 1:
        print("\t\t      Data\n")
        print(lineFormatter("\t\t      ", data))

    print("\n-------------------------------------------------------------------------------------\n")
