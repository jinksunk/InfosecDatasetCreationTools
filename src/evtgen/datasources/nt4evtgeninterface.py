'''
Created on Nov 16, 2016

@author: cstras
'''
import socket
import struct
import logging
from src.evtgen.datasources import NT4EVT
from src.evtgen.datasources.datasourceinterface import DataGenerator, DataElement, DataStore, LabelFile
from scapy.all import *

class NT4EventStore(DataStore):
    '''
    Represents a general generator of NT4EventLogRecords instances.  
    '''
    mylog = logging.getLogger(__name__)

    def __init__(self):
        '''
        Interface Constructor
        '''
        super(NT4EventStore, self).__init__()
        self.supported_source = NT4EVT

    def add_event(self, event):
        '''
        Add the event to our local event list.
        '''
        super(NT4EventStore, self).add_event(event)
        
        # If the event contains packets, add them to the overall packet list:
        dilist = event.get_datainstances(self.supported_source)
        self.mylog.debug("Adding {} nt4evt lines for event {}".format(len(dilist), event.get_id()))
        if dilist is not None:
            # Insert log elements into list in timestamp sorted order:
            for d in dilist:
                element = EventNT4EVT(d)
                self.mylog.debug("Adding data element time:{} eventid:{} to list.".format(
                    element.get_time(),
                    event.get_id()
                    ))
                self.data_list.append(element)
            
    def write(self, target):
        '''
        From the Interface Definition - this will write the packets to the given file descriptor.
        '''
        self.mylog.info("Writing {} nt4evt log records to file {}".format(len(self.data_list), target))

        with open(target, 'w') as ntLogOut:
            for nt4event in self.data_list:
                ntLogOut.write(nt4event.get_raw_element())

class NT4LabelFile(LabelFile):
    mylog = logging.getLogger(__name__)
    
    def __init__(self, datasource):
        super(NT4LabelFile, self).__init__()
    
    def write(self, target):
        with open(target, 'w') as ntLabelOut:
            for line in self.windowsNTGenerator.getLogLineIdentifiers():
                ntLabelOut.write("{0}\n".format(line))

class NT4EVTGenerator(DataGenerator):
    '''
    This class produces log lines in CSV format with the following fields:
    <ID>,<EPOCHTS>,<EVENTID>,<EVENTCODE>,<STRING>
    <ID>,<EPOCHTS>,<EVENTID>,<EVENTCODE>,<STRING>

    The following methods are provided:
    __init__(String fileLocation) - creates the class with the inital set
        of entries as given in the file at fileLocation.

    List<string> getLogEntries() - Return the list of log lines

      dictionary objects { ID:<id>, EPOCHTS:<ts>, EVENTID:<evtid>,
                           EVENTCODE:<evtcode>, MESSAGE:<logMessage> }

    None addLogEntry(List values) - Insert an entry to the log file with
                          list values: [epochts, eventid, eventcode, string]
                          The current set of records will have the IDs adjusted
                          and this entry will be inserted where the timestamp
                          fits.
    """
    Represents a general generator of NT4 event log lines.
    Includes methods to return the generated instances.

    It is intended that the __init__ constructors will take in the required
    parameter information
    '''
    mylog = logging.getLogger(__name__)

    def __init__(self, **kwargs):
        '''
        Interface Constructor
        '''
        print ("Interface unimplemented.  Use a subclass instead.")
    
class EventNT4EVT(DataElement):
    '''
    Represents an NT4EVT log line wrapped in the datasource DataElement interface.
    '''
    mylog = logging.getLogger(__name__)

    def __init__(self, nt4evtline):
        '''
        Initialize a packet data element, where the packet is produced by SCAPY
        '''
        self.wrapped = nt4evtline
        super(EventNT4EVT, self).__init__(self.get_time(), 
                                          self.get_eventID(), nt4evtline)
        
    def get_eventID(self):
        '''
        Return the event ID for this log line:
        '''
        self.mylog.debug("Extracting ID from NT4EVT log line: {}".format(self.wrapped))
        eventid = self.wrapped.split(",")[0]
        return eventid
    
    def get_time(self):
        '''
        Return the timestamp for this log line:
        '''
        self.mylog.debug("Extracting time from NT4EVT log line: {}".format(self.wrapped))
        timestamp = self.wrapped.split(",")[1]
        return timestamp