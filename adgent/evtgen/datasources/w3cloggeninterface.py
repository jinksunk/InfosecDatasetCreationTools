'''
Created on Jan 30, 2017

@author: cstras
'''
import socket
import struct
import logging
import datetime
from evtgen.datasources import W3CEVT
from evtgen.datasources.datasourceinterface import DataGenerator, DataElement, DataStore, LabelFile
from scapy.all import *

class W3CEventStore(DataStore):
    '''
    Represents a store of `W3C extended log file compliant`__ log instances.  
    
    .. _W3C: https://www.w3.org/TR/WD-logfile.html

    __ W3C_
    '''
    mylog = logging.getLogger(__name__)

    def __init__(self):
        '''
        Interface Constructor
        '''
        super(W3CEventStore, self).__init__()
        self.supported_source = W3CEVT

    """
    def add_event(self, event):
        '''
        Add the event to our local event list.
        '''
        super(W3CEventStore, self).add_event(event)
        
        # If the event contains w3c log lines

        dilist = event.get_datainstances(self.supported_source)
        self.mylog.debug("Adding {} w3c lines for event {}".format(len(dilist), event.get_id()))
        if dilist is not None:
            # Insert log elements into list in timestamp sorted order:
            for d in dilist:
                self.mylog.debug("Adding data element time:{} eventid:{} to list.".format(
                    d.get_time(),
                    d.get_eventID()
                    ))
                self.data_list.append(d)
    """
            
    def write(self, target):
        '''
        From the Interface Definition - this will write the packets to the given file descriptor.
        '''
        self.mylog.info("Writing {} w3cevt log records to file {}".format(len(self.get_datalist()), target))

        with open(target, 'w') as w3cLogOut:
            for w3cevent in self.get_datalist():
                self.mylog.debug("Event: {}, Time: {}, Line: {}".format(
                    w3cevent.get_eventID(), 
                    w3cevent.get_time(), 
                    w3cevent.get_raw_element()))
                print (w3cevent.get_raw_element(), file=w3cLogOut)
                
        # Also write out labels:
        labels = W3CLabelFile(self)
        labels.write("{}-labels".format(target))

class W3CLabelFile(LabelFile):
    '''
    A label set which uniquely identifies each record. For a W3C file, this includes the features:
    * Date Time
    * ClientIP
    * ServerIP
    * Method
    * PerSecond Count 
    * EventID
    '''
    mylog = logging.getLogger(__name__)
    
    def __init__(self, datasource):
        super(W3CLabelFile, self).__init__(datasource)
    
    def write(self, target):
        label_hash = dict()
        with open(target, 'w') as w3cLabelOut:
            for di in self.datasource.get_datalist():
                tple = "{},{},{},{}".format(di.get_datetime(), di.get_cip(), di.get_sip(), di.get_method())
                if tple not in label_hash:
                    label_hash[tple] = 0
                label_hash[tple] += 1
                print("{},{},{}".format(tple,label_hash[tple], di.get_eventID()),file=w3cLabelOut)

class W3CEVTGenerator(DataGenerator):
    '''
    This class produces log lines in `W3C extended log format`__ .

    .. _W3C: https://www.w3.org/TR/WD-logfile.html

    __ W3C_

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
    Represents a general generator of W3C event log lines.
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
    
class EventW3CEVT(DataElement):
    '''
    Represents a W3C compliant log line wrapped in the datasource DataElement interface.
    '''
    mylog = logging.getLogger(__name__)

    default_kwargs = {"datetime": datetime.datetime.now(),
                        "cip": None,
                        "cusername": "-",
                        "sip": None,
                        "sport": '80',
                        "csmethod": "GET",
                        "csuristem": "-",
                        "csuriquery": "-",
                        "scstatus": "200",
                        "csua": "-",
                        "eventid": None
                       } 
    
    def __init__(self, **kwargs):
        '''
        Initialize the data element with the following possible keyword arguments:
        * datetime -- default datetime.isoformat(sep=' ')
        * cip -- <required>
        * cusername -- default '-'
        * sip -- <required>
        * sport -- default '80'
        * csmethod -- default 'GET'
        * csuristem -- default '-'
        * csuriquery -- default '-'
        * scstatus -- default 200
        * csua -- default '-'
        * eventID -- required
        '''
        self.mylog.debug("Creating new W3CLog entry object id: {} from dict ID: {}")
        self.field_values = dict()
        for arg in self.default_kwargs.keys():
            if arg in kwargs:
                self.field_values[arg] = kwargs[arg]
            else:
                if self.default_kwargs[arg]:
                    self.field_values[arg] = self.default_kwargs[arg]
                else:
                    raise TypeError("Missing required argument {}".format(arg))
        
        self.field_values['datetime'] = datetime.datetime.fromtimestamp(
            self.field_values['datetime']).isoformat(' ')

        super(EventW3CEVT, self).__init__(self.get_time(), 
                                          self.get_eventID(), self.get_raw_element())
        
    def get_eventID(self):
        '''
        Return the event ID for this log line:
        '''
        return self.field_values["eventid"]
    
    def get_datetime(self):
        return self.field_values["datetime"]

    def get_cip(self):
        return self.field_values["cip"]

    def get_sip(self):
        return self.field_values["sip"]

    def get_method(self):
        return self.field_values["csmethod"]
    
    def get_time(self):
        '''
        Return the timestamp, in epoch format, for this log line:
        '''
        self.mylog.debug("Extracting time from W3CEVT log line: {}".format(self))
        timestamp = "{}".format(self.field_values["datetime"])
        return timestamp
    
    def get_raw_element(self):
        return "{} {} {} {} {} {} {} {} {} {}".format(
            self.field_values["datetime"],
            self.field_values["cip"],
            self.field_values["cusername"],
            self.field_values["sip"],
            self.field_values["sport"],
            self.field_values["csmethod"],
            self.field_values["csuristem"],
            self.field_values["csuriquery"],
            self.field_values["scstatus"],
            self.field_values["csua"]
            )
        
    def __str__(self, *args, **kwargs):
        return self.get_raw_element()