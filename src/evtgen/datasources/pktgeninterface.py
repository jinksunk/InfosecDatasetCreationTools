'''
Created on Nov 16, 2016

@author: cstras
'''
import socket
import struct
import logging
import locale
from evtgen.datasources.datasourceinterface import DataGenerator, DataElement, DataStore, LabelFile
from evtgen.datasources import PCAP
from scapy.all import *

class PacketStore(DataStore):
    '''
    Represents a general generator of pcap instances.  Defines a method, generate, 
    to generate events and return appropriate indicators (for example, libPCAP
    packets, or log file lines).  Includes methods to return the generated
    instances.

    It is intended that the __init__ constructors will take in the required
    parameter information
    '''
    mylog = logging.getLogger(__name__)

    def __init__(self):
        '''
        Interface Constructor
        '''
        super(PacketStore, self).__init__()
        self.supported_source = PCAP
        
    def add_event(self, event):
        '''
        Add the event to our local event list.
        '''
        super(PacketStore, self).add_event(event)
        
        # If the event contains packets, add them to the overall packet list:
        dilist = event.get_datainstances(self.supported_source)
        self.mylog.debug("Adding {} packets for event {}".format(len(dilist), event.get_id()))
        if dilist is not None:
            # Insert packet elements into list in timestamp sorted order:
            for d in dilist:
                element = DataElement(d.time, event.get_id(), d)
                self.mylog.debug("Adding data element time:{} eventid:{} to list.".format(
                    d.time,
                    event.get_id()
                    ))
                self.data_list.append(element)
            

    def write(self, target):
        '''
        From the Interface Definition - this will write the packets to the given file descriptor.
        '''
        self.data_list.sort(key=lambda x: x.get_timestamp(), reverse=False)
        self.mylog.info("Writing {} packets to file {}".format(len(self.data_list), target))
        wrpcap(target, [x.get_raw_element() for x in self.data_list])
        '''
        for de in self.data_list:
            wrpcap(target, de.get_raw())
        '''

class PacketGenerator(DataGenerator):
    '''
    Represents a general generator of pcap instances.  Defines a method, generate, 
    to generate events and return appropriate indicators (for example, libPCAP
    packets, or log file lines).  Includes methods to return the generated
    instances.

    It is intended that the __init__ constructors will take in the required
    parameter information
    '''
    mylog = logging.getLogger(__name__)

    def __init__(self):
        '''
        Interface Constructor
        '''
        print ("Interface unimplemented.  Use a subclass instead.")

    def ip2long(self,ip):
        """
        Convert an IP string to long
        """
        packedIP = socket.inet_aton(ip)
        return struct.unpack("!L", packedIP)[0]

    def long2ip(self,longval):
        """
        Convert a long value to an IP address
        """
        return socket.inet_ntoa(struct.pack('!L', longval))

    def getPCAPTimeValueRanges(self,pcapFile):
        """
        Given a pcap file path, get the min and max timestamps in the file.
        """
        TCPDUMP=("/usr/sbin/tcpdump","-tt","-q","-n","-n","-r",pcapFile)
        self.mylog.debug("Executing {}".format(" ".join(TCPDUMP)))
        output = subprocess.check_output(TCPDUMP)
        lines = output.decode(locale.getpreferredencoding(False)).split(os.linesep)
        self.mylog.debug("Generated output of {} lines (ex: {})".format(len(lines), "\n".join(lines[1:5])))
        slist = [x for x in map(int, map(float, [x.split(" ")[0] for x in
            lines[1:len(lines)-2]]))]
        startts = min(slist)
        endts = max(slist)
        #int(float(lines[len(lines) - 2].split(" ")[0]))
        self.mylog.debug("Extracted time range [{},{}]".format(startts,endts))
        return [startts,endts]
    
class TCPSession(object):
    '''
    Represents a TCP session, providing methods and data to control
    aspects of the communication such as maximum packet delay, source 
    (client) IP, destination (server) IP, source port, destination port,
    initial timestamp, and whether to randomize packetid or make it sequential.
    '''

    mylog = logging.getLogger(__name__)

    ip1 = "127.0.0.1"
    ip2 = "127.0.0.2"
    clientSourceMin = 49152
    clientSourceMax = 65535
    serverDestination = 80
    idMin = 0
    idMax = 65535

    def __init__(self, clientIP = "127.0.0.1", serverIP = "127.0.0.2",
                 sourcePortMin = 49152, sourcePortMax = 65535,
                 destinationPort = 80,
                 startTimeStamp = 1234567890, randomTimestampMax = 2,
                 randomPacketIDs = True):
        '''
        clientIP - The source IP address; defaults to 127.0.0.1
        serverIP - The destination IP address; defaults to 127.0.0.2
        sourcePortMin/Max - Source port will be randomly determined between
                            Min (inclusive) and Max (exclusive)
        destinationPort - Destination port number; defaults to 80
        startTimeStamp - Initial timestamp; defaults to 1234567890
        randomTimestampMax - Maximum interval between packets; subsequent
                             packets are generated with a delay chosen
                             between 0 and randomTimestampMax according to
                             a uniform distribution.  If set to 0, the 
                             timestamp will never be incremented.
        randomPacketIDs - Whether to select the IP packet IDs randomly
                          (default), or sequentially (starting at a random number).
        '''
        self.ip1 = clientIP
        self.ip2 = serverIP
        self.clientSourceMin = sourcePortMin
        self.clientSourceMax = sourcePortMax
        self.dPort = destinationPort
        self.timeStamp = startTimeStamp
        self.randomTimestampMax = randomTimestampMax
        self.randomPacketIDs = randomPacketIDs
        self.packetID = random.randrange(0, 65535)
        self.sPort = random.randrange(self.clientSourceMin, self.clientSourceMax)

    def genTCPHandshake(self):
        '''
        Generate three packets constituting the classic TCP 3-way handshake.
        Returns a list of three packets, no data in any of them (Syn, Syn/Ack,
        and Ack).
        '''
        p1 = self.genClientPacket()
        p1[scapy.all.TCP].flags = 'S'
        p2 = self.genServerSynAckPacket()
        p3 = self.genClientAckPacket(p2)
        return [p1,p2,p3]

    def getTimestamp(self):
        '''
        Return the next packet timestamp according to the timestamp production
        policy.  Subsequent calls will continue to produce timestamps
        regardless of whether it is used or not.
        '''
        self.timeStamp = random.randrange(
                self.timeStamp,
                self.timeStamp + self.randomTimestampMax)
        return self.timeStamp

    def genClientPacket(self):
        '''
        Returns a client packet (IP/TCP) with no payload, and with the source
        port, destination port, timestamp, and packet ID set according to the 
        defined policy.
        '''
        #TD# - Generate sequence numbers appropriately?
        p = Ether(dst="aa:bb:cc:dd:ee:ff",src="11:22:33:44:55:66",type=0x0800)/scapy.all.IP(src=self.ip1,dst=self.ip2)/scapy.all.TCP(sport=self.sPort,dport=self.dPort)
        #p = IP(src=self.ip1,dst=self.ip2)/TCP(sport=self.sPort,dport=self.dPort)
        p[scapy.all.IP].time = self.getTimestamp()
        p.time = p[scapy.all.IP].time
        p[scapy.all.IP].id = self.getPacketID()
        return p

    def genServerPacket(self):
        #TD# - Generate sequence numbers appropriately?
        #p = Ether()/IP(src=self.ip2,dst=self.ip1)/TCP(sport=self.dPort,dport=self.sPort)
        p = Ether(dst="11:22:33:44:55:66",src="aa:bb:cc:dd:ee:ff",type=0x0800)/scapy.all.IP(src=self.ip2,dst=self.ip1)/scapy.all.TCP(sport=self.dPort,dport=self.sPort)
        p[scapy.all.IP].time = self.getTimestamp()
        p.time = p[scapy.all.IP].time
        p[scapy.all.IP].id = self.getPacketID()
        return p

    def genServerSynAckPacket(self):
        p = self.genServerPacket()
        p[scapy.all.TCP].seq = random.randrange(1,3872114628)
        p[scapy.all.TCP].ack = 1
        p[scapy.all.TCP].flags = 'SA'
        return p

    def genClientAckPacket(self,ackPacket):
        '''
        Given a syn ack packet, will return a final ack packet (as part of the
        three-way handshake) which contains the correct sequence and
        ackowledgement numbers.

        Returns the packet.
        '''
        p = self.genClientPacket()
        p[scapy.all.TCP].seq = ackPacket[scapy.all.TCP].ack
        p[scapy.all.TCP].ack = ackPacket[scapy.all.TCP].seq+1
        p[scapy.all.TCP].flags = 'A'
        return p

    def getPacketID(self):
        '''
        Returns a packet ID according to the session policy, ensuring that it
        does not exceed the maximum allowed ID value.
        '''
        if self.randomPacketIDs:
            self.packetID = random.randrange(self.idMin, self.idMax)
        else:
            self.packetID = (self.packetID + 1) % 65535
        return self.packetID

class PacketLabelFile(LabelFile):
    mylog = logging.getLogger(__name__)
    
    def __init__(self, datasource):
        super(PacketLabelFile, self).__init__()
    
    def write(self, target):
        """
        Write a label file, giving each packet it in the list a value > 0, 
        corresponding to the event under consideration.  In general, will try
        to distribute packets evenly across events.
        """
        with open(target, 'w') as wFile:
            for line in self.packetGenerator.getPacketIdentifiers():
                wFile.write("{0}\n".format(line))