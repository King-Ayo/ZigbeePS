# -*- coding: utf-8 -*-
"""
Created on Thu Jul  7 10:22:31 2022

@author: falayjo1
"""
import json
import argparse
import logging
import sys
from binascii import hexlify
from builtins import input
from datetime import datetime
from io import StringIO

from cc253xemk import CC253xEMK
from packet_handler import PacketHandler, SniffedPacket
from flask import Flask
from flask import jsonify

logger = logging.getLogger(__name__)

app = Flask(__name__)

__version__ = '0.0.1'

defaults = {
    'debug_level': 'WARNING',
    'log_level': 'INFO',
    'log_file': 'pyCCSniffer.log',
    'channel': 11,
}

logger = logging.getLogger(__name__)


class DefaultHandler:
    def __init__(self, handlers=None, stats=None):
        self.stats = {} if stats is None else stats
        self.stats['Captured'] = 0
        self.stats['Non-Frame'] = 0
        self.last_timestamp = -1
        self.start_seconds = (datetime.now() -
                              datetime(1970, 1, 1)).total_seconds()
        self.times_wrapped = 0
        self.__handlers = handlers or []
        self.last_heartbeat_time = None

    def received_valid_frame(self, timestamp, mac_pdu):
        """ Dispatches any received packets to all registered handlers

        Args:
            timestamp: The timestamp the packet was received, as reported by 
                    the sniffer device, in microseconds.
            macPDU: The 802.15.4 MAC-layer PDU, starting with the Frame Control 
                    Field (FCF).
        """
        if len(mac_pdu) > 0:
            if timestamp < self.last_timestamp:
                self.times_wrapped += 1
                logger.warning(f"Timestamp wrapped - {self.times_wrapped}")

            self.last_timestamp = timestamp
            synced_timestamp = self.start_seconds + (
                (self.times_wrapped << 32) | timestamp)
            self.stats['Captured'] += 1

            packet = SniffedPacket(mac_pdu, synced_timestamp)
            for handler in self.__handlers:
                handler.handleSniffedPacket(packet)

    def received_invalid_frame(self, timestamp, frame_len, frame):
        logger.warning(
            f"Received a frame with incorrect length, pkgLen:{frame_len}, len(frame):{len(frame)}"
        )
        self.stats['Non-Frame'] += 1

    def received_heartbeat_frame(self, counter):
        current_time = datetime.now()
        delta = current_time - self.last_heartbeat_time if self.last_heartbeat_time else ""
        logger.warning(f"HEARTBEAT - {counter} - {delta}")
        self.last_heartbeat_time = current_time

    def received_unknown_command(self, cmd, payload_len, payload):
        logger.warning(
            f"UNKNOWN - CMD[{cmd:02x}] Len[{payload_len}] Bytes[{payload}]")

    def received_invalid_command(self, cmd, payload_len, payload):
        logger.warning(
            f"INVALID - CMD[{cmd:02x}] Len[{payload_len}] Bytes[{payload}]")


def arg_parser():
    debug_choices = ('DEBUG', 'INFO', 'WARNING', 'ERROR')

    parser = argparse.ArgumentParser(add_help=False,
                                     description='Read IEEE802.15.4 frames \
    from a CC2531EMK packet sniffer device, parse them and dispay them in text.'
                                     )

    in_group = parser.add_argument_group('Input Options')
    in_group.add_argument(
        '-c',
        '--channel',
        type=int,
        action='store',
        choices=list(range(11, 27)),
        default=defaults['channel'],
        help=
        f"Set the sniffer's CHANNEL. Valid range: 11-26. (Default: {defaults['channel']}",
    )
    in_group.add_argument(
        '-a',
        '--annotation',
        type=str,
        help='Include a free-form annotation on every capture.')

    log_group = parser.add_argument_group('Verbosity and Logging')
    log_group.add_argument(
        '-r',
        '--rude',
        action='store_true',
        default=False,
        help=
        'Run in non-interactive mode, without accepting user input. (Default Disabled)'
    )
    log_group.add_argument(
        '-D',
        '--debug-level',
        action='store',
        choices=debug_choices,
        default=defaults['debug_level'],
        help=
        f"Print messages of severity DEBUG_LEVEL or higher (Default {defaults['debug_level']}",
    )
    log_group.add_argument('-L',
                           '--log-file',
                           action='store',
                           nargs='?',
                           const=defaults['log_file'],
                           default=False,
                           help=f"""Log output in LOG_FILE. If -L is specified 
                                   but LOG_FILE is omitted, {defaults['log_file']} will be used.
                                   If the argument is omitted altogether,
                                   logging will not take place at all.""")
    log_group.add_argument('-l',
                           '--log-level',
                           action='store',
                           choices=debug_choices,
                           default=defaults['log_level'],
                           help=f"""Log messages of severity LOG_LEVEL or 
                                   higher. Only makes sense if -L is also 
                                   specified (Default {defaults['log_level']})"""
                           )

    gen_group = parser.add_argument_group('General Options')
    gen_group.add_argument('-v',
                           '--version',
                           action='version',
                           version=f'pyCCSniffer v{__version__}')
    gen_group.add_argument('-h',
                           '--help',
                           action='help',
                           help='Shows this message and exits')

    return parser.parse_args()


def dump_stats(stats):
    s = StringIO()

    s.write('Frame Stats:\n')
    for name, count in list(stats.items()):
        s.write(f'{name:20s}: {count}\n')

    print(s.getvalue())


def log_init():
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(getattr(logging, args.debug_level))
    cf = logging.Formatter('%(message)s')
    ch.setFormatter(cf)
    logger.addHandler(ch)

    if args.log_file:
        fh = logging.handlers.RotatingFileHandler(filename=args.log_file,
                                                  maxBytes=5000000)
        fh.setLevel(getattr(logging, args.log_level))
        ff = logging.Formatter('%(asctime)s - %(levelname)8s - %(message)s')
        fh.setFormatter(ff)
        logger.addHandler(fh)

def arg():
    a = arg_parser()
    return a


def setup(a):
    log_init()
    
    logger.info('Started logging')

    stats = {}
    packetHandler = PacketHandler(stats)
    packetHandler.enable()
    
    
    if a.annotation:
        packetHandler.setAnnotation(a.annotation)

    handler = DefaultHandler([packetHandler], stats=stats)

    snifferDev = CC253xEMK(handler, args.channel)
    
    return stats, packetHandler, snifferDev, handler

def printHelp():
    h = StringIO()
    deviceStr = str(snifferDev)
    h.write(deviceStr + '\n')
    h.write('-' * len(deviceStr) + '\n')
    h.write('Commands:\n')
    h.write('c: Print current RF Channel\n')
    h.write('h,?: Print this message\n')
    h.write('[11,26]: Change RF channel\n')
    h.write('s: Start/stop the packet capture\n')
    h.write('f: Print formated packet\n')
    h.write('d: Toggle frame dissector\n')
    h.write('a*: Set an annotation (write "a" to remove it)\n')
    h.write('p: Print all capture packets\n')
    h.write('q: Quit')
    h = h.getvalue()
    print(h)

def stuff(args, logger, packetHandler, snifferDev):
    output = []
    while 1:
        if args.rude:
            if not snifferDev.isRunning():
                snifferDev.start()
        else:
            try:
                # use the Windows friendly "raw_input()", instead of select()
                cmd = input('')

                if '' != cmd:
                    logger.debug(f'User input: "{cmd}"')
                    if cmd in ('h', '?'):
                        printHelp()
                    elif cmd == 'c':
                        # We'll only ever see this if the user asked for it, so we are
                        # running interactive. Print away
                        print(
                            f'Sniffing in channel: {snifferDev.get_channel()}'
                        )
                    elif cmd == 'd':
                        if packetHandler.isEnabled():
                            packetHandler.disable()
                            print("Dissector disabled")
                        else:
                            packetHandler.enable()
                            print("Dissector enabled")
                    elif cmd == 'p':
                        logger.info('User requested print all')
                        packetHandler.printAllFrames()
                    
                    elif cmd == 'f':
                        logger.info('User requested print in dict format')
                        fulldic = packetHandler.printFormat()
                        if fulldic is not None:
                            fulldic["Tag"] = {"Channel": snifferDev.get_channel()}
                            fulldic["Status"] = "Up"                            
                            output.append(fulldic)
                        print (output)

                    elif cmd == 'q':
                        logger.info('User requested shutdown')
                        sys.exit(0)
                    elif cmd == 's':
                        if snifferDev.isRunning():
                            snifferDev.stop()
                            print("Stopped")
                        else:
                            snifferDev.start()
                            print("Started")
                    elif 'a' == cmd[0]:
                        if 1 == len(cmd):
                            packetHandler.setAnnotation('')
                        else:
                            packetHandler.setAnnotation(cmd[1:].strip())
                    elif int(cmd) in range(11, 27):
                        snifferDev.set_channel(int(cmd))
                        print(
                            f'Sniffing in channel: {snifferDev.get_channel()}'
                        )
                    else:
                        print("Channel must be from 11 to 26 inclusive.")
            except ValueError:
                print('Unknown Command. Type h or ? for help')

@app.route('/api/get-zigbeeData')
def Zigbee():
    snifferDev.start()
    snifferDev.set_channel(int(25))
    
    while 1:
        fulldic = packetHandler.value()
        fulldic["Tag"] = {"Channel": snifferDev.get_channel()}
        fulldic["Status"] = "Up"
        return fulldic
    
    #return "Yes"

 # Returns Zigbee Packet

if __name__=="__main__":
    args = arg()
    log_init()
    stats, packetHandler, snifferDev, handler = setup(args)
    
    app.run(debug=True, port = 5008, host = "0.0.0.0")
