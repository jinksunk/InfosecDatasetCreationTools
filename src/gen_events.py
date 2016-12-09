#!/usr/local/bin/python2.7
# encoding: utf-8
'''
gen_events -- shortdesc

gen_events is a description

It defines classes_and_methods

@author:     user_name

@copyright:  2016 organization_name. All rights reserved.

@license:    license

@contact:    user_email
@deffield    updated: Updated
'''

import sys
import os
import logging
import dumper
from evtgen.datasources import PCAP, NT4EVT

from argparse import ArgumentParser
from argparse import RawDescriptionHelpFormatter
from evtgen.genfactory import genfactory

__all__ = []
__version__ = 0.1
__date__ = '2016-11-16'
__updated__ = '2016-11-16'

DEBUG = 0
TESTRUN = 0
PROFILE = 0

class CLIError(Exception):
    '''Generic exception to raise and log different fatal errors.'''
    def __init__(self, msg):
        super(CLIError).__init__(type(self))
        self.msg = "E: %s" % msg
    def __str__(self):
        return self.msg
    def __unicode__(self):
        return self.msg

def main(argv=None): # IGNORE:C0111
    '''Command line options.'''

    if argv is None:
        argv = sys.argv
    else:
        sys.argv.extend(argv)

    program_name = os.path.basename(sys.argv[0])
    program_version = "v%s" % __version__
    program_build_date = str(__updated__)
    program_version_message = '%%(prog)s %s (%s)' % (program_version, program_build_date)
    program_shortdesc = __import__('__main__').__doc__.split("\n")[1]
    program_license = '''%s

  Created by user_name on %s.
  Copyright 2016 organization_name. All rights reserved.

  Licensed under the Apache License 2.0
  http://www.apache.org/licenses/LICENSE-2.0

  Distributed on an "AS IS" basis without warranties
  or conditions of any kind, either express or implied.

USAGE
''' % (program_shortdesc, str(__date__))

    try:
        # Setup argument parser
        parser = ArgumentParser(description=program_license, formatter_class=RawDescriptionHelpFormatter)
        parser.add_argument("-v", "--verbose", dest="verbose", action="count", help="set verbosity level [default: %(default)s]")
        parser.add_argument("-f", "--pcapfile", dest="pcapfile", help="source pcap file to generate packets for", metavar="PF" )
        parser.add_argument("-o", "--outfile", dest="outfile", help="path to file to write generated packets to", metavar="OF" )
        parser.add_argument("-l", "--logoutfile", dest="logoutfile", help="path to file to write generated audit log messages to", metavar="OF" )
        parser.add_argument("-n", "--numevents", dest="numevents", help="The number of events to generate", metavar="NE" )
        parser.add_argument("-t", "--eventtype", dest="eventtype", help="The type of event to generate", metavar="EV" )
        parser.add_argument("-s", "--listtypes", dest="listtypes", action="store_true", help="List the available event types")
        parser.add_argument('-V', '--version', action='version', version=program_version_message)

        # Process arguments
        args = parser.parse_args()
        verbose = args.verbose
        
        if verbose > 0:
            logging.basicConfig(format='[%(created)f] %(levelname)s %(filename)s:%(lineno)d - %(message)s', level=logging.DEBUG)
        else:
            logging.basicConfig(format='[%(created)f] %(levelname)s %(filename)s:%(lineno)d - %(message)s', level=logging.INFO)
        
        mylog = logging.getLogger(__name__)
        mylog.info("Initialized logging for {}; level set to: {}".format(__name__, mylog.getEffectiveLevel()))

        gf = genfactory()

        if args.listtypes:
            print("Available event types:")
            # Add support for listing available event types
            print("\n\t".join(gf.get_available_generators()))
            sys.exit(0)

        # Determine how many events to generate of what type
        # Determine what type of event to generate
        mylog.info("Instantiating generator for {} events".format(args.eventtype))
        generator = gf.get_instance(args.eventtype)
        
        # Generate the events; write them to the indicated file(s)
        mylog.info("Generating {} events of type {}.".format(args.numevents, args.eventtype))
        generator.generate(args.numevents, pcapfile=args.pcapfile)
        
        # Setup location dictionary:
        locations = dict()
        if args.logoutfile is not None:
            locations[NT4EVT] = args.logoutfile
            mylog.debug("Writing event log messages to file {}".format(locations[NT4EVT]))
        if args.outfile is not None:
            locations[PCAP] = args.outfile
            mylog.debug("Writing pcap traces to file {}".format(locations[PCAP]))

        generator.write(locations)

        return 0
    except KeyboardInterrupt:
        ### handle keyboard interrupt ###
        return 0
    except Exception as e:
        logging.exception("Exception: {}".format(e))
        return 2

if __name__ == "__main__":
    if DEBUG:
        sys.argv.append("-h")
        sys.argv.append("-v")
    if TESTRUN:
        import doctest
        doctest.testmod()
    if PROFILE:
        import cProfile
        import pstats
        profile_filename = 'gen_events_profile.txt'
        cProfile.run('main()', profile_filename)
        statsfile = open("profile_stats.txt", "wb")
        p = pstats.Stats(profile_filename, stream=statsfile)
        stats = p.strip_dirs().sort_stats('cumulative')
        stats.print_stats()
        statsfile.close()
        sys.exit(0)
    sys.exit(main())