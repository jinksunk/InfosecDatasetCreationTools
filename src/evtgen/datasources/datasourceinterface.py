'''
Created on Nov 16, 2016

@author: cstras
'''

import uuid
import logging
import sys

class DataGenerator(object):
    '''
    Represents a general generator of data instances.

    It is intended that the __init__ constructors will take in the required
    parameter information
    '''
    mylog = logging.getLogger(__name__)


class DataStore(object):
    '''
    Represents a general generator of data instances.

    It is intended that the __init__ constructors will take in the required
    parameter information
    '''
    mylog = logging.getLogger(__name__)

    def __init__(self):
        '''
        Interface Constructor
        '''
        self.event_list = list()
        self.data_list = list()
        
    def add_event(self, event):
        '''
        Interface Definition - will add the event to the set of events from which data will be
        stored.
        '''
        self.mylog.debug("Adding event {} to event_list".format(event.get_id()))
        self.event_list.append(event)
        
    def length(self):
        '''
        Return the number of events that will be written with this data generator
        '''
        return len(self.event_list)

    def write(self, target):
        '''
        Interface Definition - will store the generated data instances appropriately to the datasource type;
        e.g. pcaps generated will be written to files. The 'target' argument is the specifier for where
        the data should be written to.
        '''
        self.mylog.error("Interface unimplemented.  Use a subclass instead.")
        sys.exit(1)
        
class DataElement(object):
    '''
    An abstracted data element which can be used with DataGenerators in a generic way
    '''
    mylog = logging.getLogger(__name__)
    
    def __init__(self, timestamp, eventid, rawdataelement):
        '''
        Initialize the data element with a timestamp, associated event identifier, and unique ID
        '''
        self.elementid = self._generate_id()
        self.timestamp = timestamp
        self.eventid = eventid
        self.rawelement = rawdataelement
        
    def get_timestamp(self):
        '''
        Return the timestamp for this data element
        '''
        return self.timestamp
    
    def get_uniqid(self):
        '''
        Return the unique GUID for this data element
        '''
        return self.uniqid
    
    def get_raw_element(self):
        '''
        Get the encapsulated data element.
        '''
        return self.rawelement
    
    def _generate_id(self):
        '''
        This base method simply generates a type-4 UUID. If a different type of ID is desired, this can
        be overridden
        '''
        self.uniqid = uuid.uuid4()
        
class LabelFile(object):
    '''
    An abstract class representing a label file in KIDS - each data source should have a corresponding
    LabelFile implementation that records the unique IDs of each event and the data instances in
    the data source that correspond to that event.
    '''
    
    mylog = logging.getLogger(__name__)
    
    def __init__(self, datasource):
        '''
        Initialize with a reference to the data source we are a label for.
        '''
        self.datasource = datasource