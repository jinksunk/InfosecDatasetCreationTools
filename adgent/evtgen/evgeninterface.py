'''
Created on Nov 20, 2016

@author: cstras
'''

import logging

class EventGenerator(object):
    '''
    Represents a general generator of events.  Defines a method, generate, 
    to generate events for available datatypes.
    '''
    mylog = logging.getLogger(__name__)


    def __init__(self):
        '''
        Interface Constructor
        '''
        self.mylog.error("Interface unimplemented.  Use a subclass instead.")

    def generate(self, numevents, **kwargs):
        '''
        Given a number of events, generate that many events.
        '''
        self.mylog.error("Interface unimplemented.  Use a subclass instead.")
        
class EventInterface(object):
    '''
    Represents a single occurrence of an Event, encapsulating the data, ID, and other components
    '''
    mylog = logging.getLogger(__name__)

    def __init__(self, EventID, **kwargs):
        self.mylog.debug("Initializing EventInterface...")
        self.myID = EventID
        self.datainstances = dict()
        
    def get_id(self):
        return self.myID
    
    def get_datainstances(self, datasource):
        self.mylog.debug("Returning data elements for event {} - source {}".format(self.get_id(), datasource))
        if datasource in self.datainstances.keys():
            return self.datainstances[datasource]
        else:
            self.mylog.warning("No data instances of type {} for event id {}".format(datasource, self.myID))
            return None
    
