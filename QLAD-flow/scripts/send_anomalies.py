#!/usr/bin/python

# NOTICE: this is a modified version of the original version from git://git.nic.cz/dns-anomaly/
# modified 2017-07-27 by Pieter Robberechts in context of implementing QLAD system at DNS Belgium
# to add ASN to each detected anomaly and group anomalies by ASN

import sys
import json
from optparse import OptionParser
from pymongo import MongoClient
import pygeoip
from tld import get_tld
from anomaly_parser import AnomalyParser, ParserError
import socket
import random
import time
import datetime
import struct
import pickle
import logging
from impala.dbapi import connect



# Setup logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s: %(message)s', datefmt='%d-%m-%Y %H:%M')
ch.setFormatter(formatter)
logger.addHandler(ch)

HOST_Graphite =   # Standard loopback interface address (localhost)
PORT = 2004        # Port to send data to
IMPALA_HOST = 
IMPALA_PORT = 21050







def main():
    # Parse CLI options
    parser = OptionParser(usage="usage: %prog [options] anomalies",
                          version="%prog 1.0")
    parser.add_option("-f", "--file",
                      dest="anomalies_file",
                      action="store",
                      type="string",
                      help="Read detected anomalies from file. Omit to use stdIn.",
                      metavar="FILE")
    parser.add_option("-t", "--type",
                      dest="anomalies_type",
                      action="store",
                      type="string",
                      help="The type of these anomalies (Domain, Resolver or Global)",
                      metavar="STRING")
    parser.add_option("-s", "--server",
                      dest="server",
                      action="store",
                      type="string",
                      help="The server which generated the traffic.",
                      metavar="STRING")
    parser.add_option("-m", "--maxmind",
                      dest="maxmind",
                      action="store",
                      type="string",
                      help="Path to maxmind database files.",
                      metavar="STRING")
    (options, args) = parser.parse_args()

    # Verify CLI options
    if not options.anomalies_file:
        options.anomalies_file = sys.stdin
    if not options.anomalies_type:
        sys.stderr.write("No type given for these anomalies.\n")
        sys.exit(-1)
    if not options.anomalies_type in ["Domain", "Resolver", "ASN"]:
        sys.stderr.write("%s is not a valid type.\n" % options.anomalies_type)
        sys.exit(-1)
    if not options.server:
        sys.stderr.write("Provide a server name.")
        sys.exit(-1)
    if not options.maxmind:
        sys.stderr.write("Provide the path to the maxmind database.")
        sys.exit(-1)

    #result = parse_anomalies(options.anomalies_file, options.anomalies_type, options.server, options.maxmind)
    #store_in_mongoDB(result)
    parse_anomalies_send_to_graphite(options.anomalies_file, options.anomalies_type, options.server)

def parse_anomalies_send_to_graphite(anomalies_file, anomalies_type, server):
    # Initialize the anomaly parser
    ap = AnomalyParser()
    try :
        ap.open_file(anomalies_file)
    except:
        sys.stderr.write("Cannot open file %s\n" % anomalies_file)
        sys.exit(-1)

    # Parse the anomalies
    formatted_anomalies = []
    while True:
        try:
            parsed_anomalies = ap.get_next_anomalies()
        except ParserError as e:
            sys.stderr.write("Error while parsing file %s: %s\n" % (e.value))
            sys.exit(-1)
        if not parsed_anomalies:
            break
        store_total_qlad_flow_graphite(parsed_anomalies.from_time, parsed_anomalies.to_time, server)
        for ip in parsed_anomalies.anomalies:
            store_anomalies_qlad_flow_graphite(parsed_anomalies.from_time, parsed_anomalies.to_time, ip,  anomalies_type, server)

    if anomalies_file is not sys.stdin:
        ap.close_file()

def parse_anomalies(anomalies_file, anomalies_type, server, maxmind):
    # Initialize the anomaly parser
    ap = AnomalyParser()
    try :
        ap.open_file(anomalies_file)
    except:
        sys.stderr.write("Cannot open file %s\n" % anomalies_file)
        sys.exit(-1)

    # Parse the anomalies
    formatted_anomalies = []
    while True:
        try:
            parsed_anomalies = ap.get_next_anomalies()
        except ParserError as e:
            sys.stderr.write("Error while parsing file %s: %s\n" % (e.value))
            sys.exit(-1)
        if not parsed_anomalies:
            break
        for ip in parsed_anomalies.anomalies:
            formatted_anomalies.append({
                'start': parsed_anomalies.from_time,
                'end': parsed_anomalies.to_time,
                'subject': ip,
                'type': anomalies_type,
                'asn': ASN_lookup(ip, anomalies_type, maxmind),
                'server': server
            })

    if anomalies_file is not sys.stdin:
        ap.close_file()

    return formatted_anomalies

def store_total_qlad_flow_graphite(begin, end, server):
    begin_dt=datetime.datetime.fromtimestamp(begin)
    end_dt = datetime.datetime.fromtimestamp(end)
    total_sql = """
SELECT FLOOR(time/1000) AS time_seconds, COUNT(*)
FROM entrada.dns 
WHERE server = '{0}' 
AND (
    (year = {1} AND month = {2} AND day = {3})
    OR (year = {4} AND month = {5} AND day = {6})
)  
AND time >= {7}
AND time < {8} 
GROUP BY FLOOR(time/1000) 
ORDER BY time_seconds
""".format(
    server, 
    begin_dt.year, begin_dt.month, begin_dt.day,
    end_dt.year, end_dt.month, end_dt.day,
    begin * 1000, 
    end * 1000
)


    #time must be in seconds
    conn = connect(host=IMPALA_HOST, port=IMPALA_PORT, use_ssl=True)
    cur = conn.cursor()
    logger.debug("Executing sql:" + total_sql)
    cur.execute(total_sql)
    stat_total = cur.fetchall()
    logger.debug("Get des of results returned by impala query" + str(cur.description))
    conn.close()


    metrics_total = []
    datetime_name = ("." + str(begin_dt.year) + "." + str(begin_dt.strftime('%m'))
                   + "." + str(begin_dt.strftime('%d')) + "." + str(begin_dt.strftime('%H')) + "." + str(begin_dt.strftime('%M')))
    server = str(server).replace(".", "_")


    metric_path_total =  "test2.flow." + server + ".total"  + datetime_name

    for i in stat_total:
        metrics_total.append((metric_path_total, (int(i[0]), int(i[1]) )))

    # Use sendall to ensure all data is sent
    payload_total = pickle.dumps(metrics_total, protocol=2)
    # Send data to Graphite
    sock = socket.socket()
    try:
        sock.connect((HOST_Graphite, PORT))
        size_total = struct.pack('!L', len(payload_total))
        sock.sendall(size_total + payload_total)
        logger.debug(f"Sent {len(payload_total)} bytes of total data to Graphite")
    finally:
        sock.close()


def store_anomalies_qlad_flow_graphite(begin, end, subject, type_, server):
   #begin, end: seconds
    begin_dt=datetime.datetime.fromtimestamp(begin)
    end_dt = datetime.datetime.fromtimestamp(end)

    if type_ == 'Resolver':
        anomaly_sql = """
SELECT FLOOR(time/1000) AS time_seconds, COUNT(*)
FROM entrada.dns 
WHERE server = '{0}' 
AND (
    (year = {1} AND month = {2} AND day = {3})
    OR (year = {4} AND month = {5} AND day = {6})
) 
AND src = '{7}' 
AND time >= {8} 
AND time < {9} 
GROUP BY FLOOR(time/1000) 
ORDER BY time_seconds
""".format(
    server, 
    begin_dt.year, begin_dt.month, begin_dt.day,
    end_dt.year, end_dt.month, end_dt.day,
    subject, 
    begin * 1000, 
    end * 1000
)

    else:
        subject1 = "%" + str(subject)
        anomaly_sql = """
SELECT FLOOR(time/1000) AS time_seconds, COUNT(*)
FROM entrada.dns 
WHERE server = '{0}' 
AND (
    (year = {1} AND month = {2} AND day = {3})
    OR (year = {4} AND month = {5} AND day = {6})
)
AND qname LIKE '{7}' 
AND time >= {8} 
AND time < {9} 
GROUP BY FLOOR(time/1000) 
ORDER BY time_seconds
""".format(
    server, 
    begin_dt.year, begin_dt.month, begin_dt.day,
    end_dt.year, end_dt.month, end_dt.day,
    subject1, 
    begin * 1000, 
    end * 1000
)


    conn = connect(host=IMPALA_HOST, port=IMPALA_PORT, use_ssl=True)
    cur = conn.cursor()
    logger.debug("Executing sql:" + anomaly_sql)
    cur.execute(anomaly_sql)
    stat_abnormal = cur.fetchall()
    logger.debug("Get des of results returned by impala query" + str(cur.description))
    conn.close()

    metrics_abnormal = []
    datetime_name = ("." + str(begin_dt.year) + "." + str(begin_dt.strftime('%m'))
                   + "." + str(begin_dt.strftime('%d')) + "." + str(begin_dt.strftime('%H')) + "." + str(begin_dt.strftime('%M')))
    #server = str(server).replace(".","_")

    metric_path_abnormal = "test2.flow." + "abnormal"  + datetime_name + ";" + type_ + "=" + subject + ";server=" + server
        #server, ip, qname (tags)

    for i in stat_abnormal:
        metrics_abnormal.append((metric_path_abnormal, (int(i[0]), int(i[1]) )))
        #convert to int python not in int numpy array (pandas)
        #logger.info(int(i[0]))
        #logger.info(int(i[1]))
    # Use sendall to ensure all data is sent
    payload_abnormal = pickle.dumps(metrics_abnormal, protocol=2)
    # Send data to Graphite
    sock = socket.socket()
    try:
        sock.connect((HOST_Graphite, PORT))
        size_abnormal = struct.pack('!L', len(payload_abnormal))
        sock.sendall(size_abnormal + payload_abnormal)
        logger.debug(f"Sent {len(payload_abnormal)} bytes of abnormal data to Graphite")
    finally:
        sock.close()




def ASN_lookup(id, anomaly_type, maxmind):
    gi = pygeoip.GeoIP(maxmind+'/GeoIPASNum.dat')
    try:
        if anomaly_type == "Resolver":
            return gi.asn_by_addr(id)
        elif anomaly_type == "Domain":
            return gi.asn_by_name(get_tld("http://"+id[:-1]))
        elif anomaly_type == "ASN":
            return id
    except:
        return "Unknown"

def store_in_mongoDB(anomalies):
    if len(anomalies):
        client = MongoClient("mongodb://admin:1@localhost:27017/admin")
        db = client['QLAD']
        result = db.anomalies.insert_many(anomalies)
        if result:
            print ("Successfull saved {} anomalies.".format(len(anomalies)))
    else:
        print ("No anomalies found.")

if __name__ == "__main__":
    main()
