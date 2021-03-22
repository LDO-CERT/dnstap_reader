#!/usr/bin/env python3
#
# dnstap_reader
# written by Luca Memini (LDO-CERT) - Luca.Memini@leonardocompany.com
# thx to Davide Arcuri

from __future__ import print_function
import io
import os
import sys
import socket
import argparse
import framestream
import ipaddress
import dns.message
import dns.rrset
import shlex
import json
import syslog
from dnstap_pb2 import Dnstap
from var_dump import var_dump
from daemonize import Daemonize
from datetime import datetime


class MyParser(argparse.ArgumentParser):
    def error(self, message):
        sys.stderr.write("error: %s\n" % message)
        self.print_help()
        print(
            "Default mode parse only Client Response (CR),"
            " use -v for show all dns query\n",
            "\n",
        )
        sys.exit(2)

def log_message(tosyslog, message):
    if tosyslog:
        syslog.syslog(message)
    else:
        print(message)

def send2logstash(json_data):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
    s.sendto(bytes(json_data, "utf-8"), (logstash_host, int(logstash_port)))

def dnsflag_fromhex(n):
    if n & int("0x8000", 16):
        return "QR (Query Response)"
    if n & int("0x0400", 16):
        return "AA (Authoritative Answer)"
    if n & int("0x0200", 16):
        return "TT (Truncated Response)"
    if n & int("0x0100", 16):
        return "RD (Recursion Desired)"
    if n & int("0x0080", 16):
        return "RA (Recursion Avaible)"
    if n & int("0x0020", 16):
        return "AD (Authentic Data)"
    if n & int("0x0010", 16):
        return "CD (Checking Disabled)"


def get_query_type(type):
    switcher = {
        1: "AQ",
        2: "AR",
        3: "RQ",
        4: "RR",
        5: "CQ",
        6: "CR",
        7: "FQ",
        8: "FR",
        9: "SQ",
        10: "SR",
        11: "TQ",
        12: "TR",
    }
    return switcher.get(type, "unknown")


def parse_frame(frame):
    dnstap_data = Dnstap()
    dnstap_data.ParseFromString(frame)
    # https://github.com/dnstap/dnstap.pb/blob/master/dnstap.proto read here!

    msg_type = dnstap_data.message.type

    if msg_type in [4, 6]: ## 6 CLIENT_RESPONSE - 4 RESOLVER_RESPONSE
        query = dns.message.from_wire(dnstap_data.message.response_message)
        q_rcode = dns.rcode.from_flags(query.flags,query.ednsflags)

        if msg_type == 6 or (msg_type == 4 and verbose):
         if not doCut or (not q_rcode == 0):
            data_dict = {
                'timestamp': dnstap_data.message.response_time_sec,
		'identity': dnstap_data.identity.decode('utf-8'),
		'version':  dnstap_data.version.decode('utf-8'),
                'query_type': get_query_type(msg_type),
                'query_address': str(ipaddress.ip_address(
                    dnstap_data.message.query_address
                )),
                'query_port': dnstap_data.message.query_port,
                'response_address': str(ipaddress.ip_address(
                    dnstap_data.message.response_address
                )),
                'response_port': dnstap_data.message.response_port,
                'response_len': len(dnstap_data.message.response_message),
                'query_id': query.id,
                'rcode_string': dns.rcode.to_text(
                    dns.rcode.from_flags(query.flags, query.ednsflags)
                ),
                'rcode': dns.rcode.from_flags(query.flags, query.ednsflags),
                'flags': dns.flags.to_text(query.flags),
		'question': [],
                'answers': [],
                'authorities':[],
            }
            for question in query.question:
               data_dict['question'].append(str(question).split("\n"))
#               data_dict['question'].append(str(question).replace("\n", " | "))
            for answer in query.answer:
               data_dict['answers'].append(str(answer).split("\n"))
#               data_dict['answers'].append(str(answer).replace("\n", " | "))
            for auth in query.authority:
               data_dict['authorities'].append(str(auth).split("\n"))
#               data_dict['authorities'].append(str(auth).replace("\n", " | "))
            send2logstash(json.dumps(data_dict))
            if tosyslog:
               log_message(tosyslog, json.dumps(data_dict))

         else:

            for answers in query.answer:
              for answer in str(answers).split("\n"):
                #data_dict['answers'].append(str(answer).split("\n"))
                data_dict = {
                  'timestamp': dnstap_data.message.response_time_sec,
  		  'identity': dnstap_data.identity.decode('utf-8'),
		  'version':  dnstap_data.version.decode('utf-8'),
                  'query_type': get_query_type(msg_type),
                  'query_address': str(ipaddress.ip_address(
                      dnstap_data.message.query_address
                  )),
                  'query_port': dnstap_data.message.query_port,
                  'response_address': str(ipaddress.ip_address(
                    dnstap_data.message.response_address
                  )),
                  'response_port': dnstap_data.message.response_port,
                  'response_len': len(dnstap_data.message.response_message),
                  'query_id': query.id,
                  'rcode_string': dns.rcode.to_text(
                      dns.rcode.from_flags(query.flags, query.ednsflags)
                  ),
                  'rcode': dns.rcode.from_flags(query.flags, query.ednsflags),
                  'flags': dns.flags.to_text(query.flags),
                  'question':[],
                  'answers': str(answer),
                  'authorities':[],
                }
                for question in query.question:
                   data_dict['question'].append(str(question).split("\n"))
                for auth in query.authority:
                   data_dict['authorities'].append(str(auth).split("\n"))

                send2logstash(json.dumps(data_dict))
                if tosyslog:
                   log_message(tosyslog, json.dumps(data_dict))

    # OTHER QUERY
    else:
        if verbose:
            query = dns.message.from_wire(dnstap_data.message.query_message)

            data_dict = {
                'timestamp': dnstap_data.message.response_time_sec,
  		'identity': dnstap_data.identity.decode('utf-8'),
		'version':  dnstap_data.version.decode('utf-8'),
                'query_type': get_query_type(msg_type),
                'query_address': str(ipaddress.ip_address(
                    dnstap_data.message.query_address
                )),
                'query_port': dnstap_data.message.query_port,
                'response_address': str(ipaddress.ip_address(
                    dnstap_data.message.response_address
                )),
                'response_port': dnstap_data.message.response_port,
                'response_len': len(dnstap_data.message.response_message),
                'query_id': query.id,
                'rcode_string': dns.rcode.to_text(
                    dns.rcode.from_flags(query.flags, query.ednsflags)
                ),
                'rcode': dns.rcode.from_flags(query.flags, query.ednsflags),
                'flags': dns.flags.to_text(query.flags),
		'question':[],
                'answers': [],
                'authorities':[],
            }
            for question in query.question:
               data_dict['question'].append(str(question).split("\n"))
##               data_dict['question'].append(str(question).replace("\n", " | "))
            for answer in query.answer:
               data_dict['answers'].append(str(answer).split("\n"))
#               data_dict['answers'].append(str(answer).replace("\n", " | "))
            for auth in query.authority:
               data_dict['authorities'].append(str(auth).split("\n"))
#               data_dict['authorities'].append(str(auth).replace("\n", " | "))

            send2logstash(json.dumps(data_dict))
            if tosyslog:
               log_message(tosyslog, json.dumps(data_dict))

def main():
    log_message(True,"Logstash host "+logstash_host+":"+logstash_port)
    if tosyslog:
       log_message(True,"Option for store copy of log locally active")
    if socketfile:
        try:
            log_message(True,"Opening socket to "+socketfile)
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.bind(socketfile)
            os.chmod(socketfile,666)
            sock.listen(1)
            while True:
                connection, client_address = sock.accept()
                log_message(True, "New incoming connection...")
                try:
                    # Ok, I need Frame Streams handshake code here.
                    # https://www.nlnetlabs.nl/bugs-script/show_bug.cgi?id=741#c15
                    log_message(True, ">> Waiting READY FRAME")
                    data = connection.recv(262144)
                    log_message(True, "<< Sending ACCEPT FRAME")
                    connection.sendall(
                        b"\x00\x00\x00\x00\x00\x00\x00\x22\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x16\x70\x72\x6f\x74\x6f\x62\x75\x66\x3a\x64\x6e\x73\x74\x61\x70\x2e\x44\x6e\x73\x74\x61\x70"
                    )
                    log_message(True, ">> Waiting START FRAME")
                    data = connection.recv(262144)
                    start = data
                    while True:
                        data = connection.recv(262144)
                        if data:
                            b = io.BytesIO(start + data)
                        for frame in framestream.reader(b):
                            parse_frame(frame)
                    else:
                        log_message(True, "error: true is not true!!!")
                finally:
                    # Clean up the connection
                    log_message(True, "Connection lost")
                    connection.close()
        finally:
            log_message(True, "Closing socket")
            sock.close()
            os.unlink(socketfile)
            syslog.closelog()

    elif tapfile:
        log_message(True, "Reading data from "+tapfile)
        for frame in framestream.reader(open(tapfile, "rb")):
            parse_frame(frame)

if __name__ == "__main__":
    parser = MyParser(description="DNSTAP reader to logstash")
    parser.add_argument("-v", "--verbose", 
                        action="store_true", help="Verbose log all query")

    parser.add_argument("-c", "--cut", 
                        action="store_true", help="Cut multiple <answers> to single event")

    parser.add_argument("-d", "--dest-host",
                        required=True, help="logstash host")

    parser.add_argument("-p", "--dest-port",
                        required=True, help="logstash port (udp)")

    parser.add_argument("-t", "--log-type", type=str, 
                        default='json', help="Type log [json|cef] (json default)")


    logdest = parser.add_mutually_exclusive_group(required=False)
    logdest.add_argument(
        "-l",
        "--to-syslog",
        action="store_true",
        help="Send copy of output to local syslog",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", help="file")
    group.add_argument("-s", "--socket", help="socket")

    args = parser.parse_args()

    logstash_host = args.dest_host
    logstash_port = args.dest_port
    tapfile = args.file
    verbose = args.verbose
    socketfile = args.socket
    tosyslog = args.to_syslog
    doCut = args.cut

    # Priority: LOG_EMERG, LOG_ALERT, LOG_CRIT,
    #           LOG_ERR, LOG_WARNING, LOG_NOTICE, LOG_INFO, LOG_DEBUG.
    # Facilities: LOG_KERN, LOG_USER, LOG_MAIL, LOG_DAEMON, LOG_AUTH,
    #             LOG_LPR, LOG_NEWS, LOG_UUCP, LOG_CRON, LOG_SYSLOG
    #             and LOG_LOCAL0 to LOG_LOCAL7.
    # Options: LOG_PID, LOG_CONS, LOG_NDELAY, LOG_NOWAIT and LOG_PERROR
    syslog.openlog(
      "DNStap", logoption=syslog.LOG_PID, facility=syslog.LOG_DAEMON
      )
    pid = "/var/run/dnstap.pid"
    daemon = Daemonize(app="DNStap", pid=pid,
                        action=main, auto_close_fds=True)

    # ok, going in to darkness
    # https://daemonize.readthedocs.io/en/latest/
    daemon.start()
