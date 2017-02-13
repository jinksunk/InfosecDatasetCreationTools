'''
Created on Nov 17, 2016

@author: cstras
'''
import imp
import os
import pkgutil
import evtgen
import importlib
import logging

class genfactory(object):
    '''
    Provides a factory pattern to produce instances of event generators. Also provides 
    methods to determine the types of generators available.
    '''
    
    mylog = logging.getLogger(__name__)

    def __init__(self):
        '''
        Constructor
        '''
        self.mylog.debug("Initializing with {} known generators:".format(len(self.get_available_generators())))
        
    def get_available_generators(self):
        '''
        This method returns a list of strings, providing the names of the available generators.
        '''
        return evtgen.generator_dict.keys()
    
    def get_instance(self, generator):
        '''
        Given a generator name, returns an instance of it.
        This method will instantiate the named generator, and return it.
        '''
        self.mylog.debug("Instantiating generator {}".format(generator))

        if not generator in evtgen.generator_dict.keys():
            raise NameError("Unknown generator specified: {}".format(generator))
            return None
        
        mymod = importlib.import_module(evtgen.generator_dict[generator])
        self.mylog.debug("Instantiating {}.{}".format(mymod, evtgen.GENCLSNAME))
        myclass = getattr(mymod, evtgen.GENCLSNAME)
        return myclass()
        