'''
Created on Nov 16, 2016

@author: cstras
'''

import scapy
from scapy.all import *
from evtgen.evgeninterface import EventGenerator, EventInterface
from evtgen.datasources import nt4evtgeninterface, pktgeninterface, PCAP, NT4EVT
from evtgen import datasources

class EventGenerator(EventGenerator):
    '''
    Generates events of the implemented type.
    '''
    
    mylog = logging.getLogger(__name__)
    produced_types = [PCAP, NT4EVT]
    
    def __init__(self):
        self.datasourcetypes = [PCAP, NT4EVT]
        self.nextid = 1 # The next event ID to use
        self.evtinstances = dict() # A mapping from event IDs to event instances
        self.genmap = dict()
        self.genmap[PCAP] = CodeRedPacketGenerator()
        self.genmap[NT4EVT] = CodeRedNT4EVTGenerator()
        self.stormap = dict()
        self.stormap[PCAP] = pktgeninterface.PacketStore()
        self.stormap[NT4EVT] = nt4evtgeninterface.NT4EventStore()

        self.mylog.debug("Initialized.")
        
    def generate(self, numevents, **kwargs):
        '''
        Will generate numevents event objects, corresponding to CodeRed propagation attempts.
        **kwargs may include:
          pcapfile => the location of the pcap source file, if any
          ntlogfile => the location of the ntlog source file, if any
          timerangestart => a start time
          timerangeend => an end time
        '''
        self.evarray = list()
        
        # Set the timestamp range
        if "pcapfile" in kwargs.keys():
            self.mylog.debug("Extracting timerange from pcap file: {}".format(kwargs["pcapfile"]))
            (timestampstart,timestampend) = \
                self.genmap[PCAP].getPCAPTimeValueRanges(kwargs["pcapfile"])
        elif "timerangestart" in kwargs.keys() and "timerangeend" in kwargs.keys():
            timestampstart = kwargs["timerangestart"]
            timestampend = kwargs["timerangeend"]
        else:
            raise ValueError("Either pcapfile or both timerangestart and timerangeend must be defined.")
            
        if (timestampstart > timestampend):
            raise ValueError(
                "Derived time period is of 0 (or shorter) length ({0},{1})".format(
                    timestampstart,timestampend))
        self.mylog.debug('Start TS: %d ; End TS: %d'%(timestampstart, timestampend))

        for i in range(0,int(numevents)):
           self.evtinstances[self.nextid] = self._generate_single(self.nextid, timestampstart, timestampend)
           for store in self.stormap:
               self.stormap[store].add_event(self.evtinstances[self.nextid])

           self.nextid = self.nextid + 1
        
    def _generate_single(self, eventid, startts, endts):
        '''
        For code red, we need to generate a set of packets produced by the attempt, and then
        generate a log entry corresponding to the exploit request packet.
        '''
        self.mylog.debug("Generating event ID: {}".format(eventid))
        
        # Generate packets first
        plist = self.genmap[PCAP].get_packets(startts, endts)
        
        if len(plist) != 3:
            raise ValueError(
                "Error: generated {} packets instead of 3.".format(len(plist)))
            
        log_timestamp = plist[2].time
        # Next, get the timestamp of the third packet (the ack), and generate a log entry
        # corresponding to the parameters of the packet:
        self.mylog.debug("Generating a logline for timestamp {}".format(log_timestamp))

        loglist = self.genmap[NT4EVT].get_lines(plist[2].time, plist[2][scapy.all.IP].src)

        # Finally, return an event object.
        kwargs = {PCAP: plist, NT4EVT: loglist}
        toreturn = CodeRedPropagationAttemptEvent(eventid, **kwargs)

        return toreturn

    def write(self, locmap, **kwargs):
        '''
        Writes data associated with all events to the destinations specified in kwargs.
        
        locmap should provide a map from datasource type to destination specification, e.g.:
        { evtgen.datasources.PCAP: "/tmp/packets.pcap", ... }
        '''
        
        ## For each data store, call the write method.

        for dtype in locmap.keys():
            if dtype in self.produced_types:
                self.mylog.debug("Will write type {}? {}".format(dtype, dtype in self.produced_types))
                ## TODO: Replace this with data store; we don't want to write from the generator
                self._get_datastore(dtype).write(locmap[dtype])
            else:
                self.mylog.warn("Datatype {} not produced by this module; writing nothing.".format(dtype))
        

    def _get_generator(self, dtype):
        '''
        Given a data type, return the generator implementation used by this class. 
        '''
        if not dtype in self.genmap.keys():
            raise ValueError("Unknown type {}".format(dtype))

        return self.genmap[dtype]
    
    def _get_datastore(self, dtype):
        '''
        Given a data type, return the datastore implementation used by this class. 
        '''
        if not dtype in self.stormap.keys():
            raise ValueError("Unknown datastor type {}".format(dtype))

        return self.stormap[dtype]
        
class CodeRedPropagationAttemptEvent(EventInterface):
    '''
    A single instance of a code red propgation attempt. Includes packets and event log messages.
    '''
    
    mylog = logging.getLogger(__name__)
    
    def __init__(self,
                 EventID,
                 **kwargs):
        '''
        Create an instantiation of an Event with code-red packets, log lines, and the given event ID.
        kwargs should be a mapping from data type (as given in datasources) to a list of raw data instances,
        e.g.: {datasources.PCAP: packetlist, ...}
        '''
        self.mylog.debug("Initializing CodeRedPropagationAttemptEvent for event ID {}".format(EventID))
        super(CodeRedPropagationAttemptEvent, self).__init__(EventID)
        
        for source in kwargs.keys():
            self.mylog.debug("Adding {} data elements for source {}...".format(len(kwargs[source]), source))
            self.datainstances[source] = kwargs[source]

class CodeRedPacketGenerator(pktgeninterface.PacketGenerator):
    '''
    Generates packets consistent with CodeRed propagation events, producing both packet instances and
    nt log file instances.  Includes method to getPackets() and
    getNTLogMessages()
    '''
    mylog = logging.getLogger(__name__)
    packetData = "GET default.ida?NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN%u9090%u6858%ucbd3%u7801%u9090%u6858%ucbd3%u7801%u9090%u6858%ucbd3%u7801%u9090%u9090%u8190%u00c3%u0003%u8b00%u531b%u53ff%u0078%u0000%u00=a HTTP/1.0\r\n\r\n"
    
    def __init__(self, **kwargs):
        '''
        Loads the required information to generate packets. 
        kwargs can include:
        * sstart - the starting IP address for the source address range (integer)
        * send - the ending IP address for the source address range (integer)
        * dstart - the starting IP address for the destination address range (integer)
        * dend - the ending IP address for the destination address range (integer)
        '''
        self.sstart = self.dstart = 0
        self.send = self.dend = math.pow(2, 32)-1

        if "sstart" in kwargs.keys():
            self.sstart = kwargs.sstart
        if "send" in kwargs.keys():
            self.send = kwargs.send
        if "dstart" in kwargs.keys():
            self.dstart = kwargs.dstart
        if "dend" in kwargs.keys():
            self.dend = kwargs.dend
        
    def get_packets(self, timestampstart, timestampend, **kwargs):
        '''
        This method will return a sequence of packets which includes
        a TCP handshake, along with an HTTP GET request with data from CodeRed.
        Will set valid IP addresses chosen from the
        appropriate ranges, valid starting timestamp chosen from the appropriate
        range, and random packet ID value.

        kwargs can include:
          
        Returns: a list of packets created for this attack.
        '''
        self.mylog.info('Initializing Packet Generator: Start TS: %d ; End TS: %d'%(timestampstart, timestampend))

        ## Set parameters:
        sip = int(random.random() * (self.send - self.sstart) +
                   self.sstart)
        dip = int(random.random() * (self.dend - self.dstart) +
                   self.dstart)
        startTimestamp = int(random.random() * (timestampend -
                                            timestampstart) +
                   timestampstart)
        self.mylog.info('Creating attack with: time: {} ; sip: {}({}) ; dip: {}({})'.format(
            startTimestamp, sip, self.long2ip(sip), dip, self.long2ip(dip)))

        ## Create attack packets
        ts = pktgeninterface.TCPSession(clientIP = self.long2ip(sip),
                        serverIP = self.long2ip(dip),
                        startTimeStamp = startTimestamp)

        plist = ts.genTCPHandshake()

        ## Add payload
        ptime = plist[2][scapy.all.IP].time
        plist[2][scapy.all.TCP] = plist[2][scapy.all.TCP]/self.packetData
        plist[2][scapy.all.IP].time = ptime
        plist[2].time = ptime

        return plist

class CodeRedNT4EVTGenerator(nt4evtgeninterface.NT4EVTGenerator):
    '''
    Generates log lines consistent with parsed NT4EVT records, formatted as CSV lines.
    Includes data that might be recorded for a code red attack.
    '''
    mylog = logging.getLogger(__name__)
    logline = r"HTTPGetParameter=/default.ida?NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN%u9090%u6858%ucbd3%u7801%u9090%u6858%ucbd3%u7801%u9090%u6858%ucbd3%u7801%u9090%u9090%u8190%u00c3%u0003%u8b00%u531b%u53ff%u0078%u0000%u00=a HTTP/1.0\r\n\r\n"
    event_id = 50010
    event_code = 50011
    
    def __init__(self, **kwargs):
        '''
        Loads the required information to generate packets. 
        '''
        super(CodeRedNT4EVTGenerator, self).__init__(**kwargs)
        
    def get_lines(self, timestamp, sourceip, **kwargs):
        '''
        This method will return a formatted log line in a single element list
        corresponding to the parameters passed in.

        kwargs can include: Nothing for this class
          
        Returns: a list of packets created for this attack.
        '''
        self.mylog.info('Initializing NT4LogLine Generator: time={}, sourceip={}'.format(
            timestamp, sourceip))

        ## Set parameters: TS,EID,ECD,SRC,MSG
        lline = "{},{},{},{},{}".format(timestamp, self.event_id, self.event_code, sourceip, self.logline)

        self.mylog.debug('Generated log line: "{}"'.format(lline))
        retlist = [lline]
        return retlist