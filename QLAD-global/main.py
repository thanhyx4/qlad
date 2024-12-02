#!/usr/bin/python

# QLAD - An anomaly detection system for DNS traffic
# Copyright (C) 2017 DNS Belgium
#
# This file is part of QLAD.
#
# QLAD is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# QLAD is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with QLAD.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import division
from impala.dbapi import connect
from math import log10
from optparse import OptionParser
from pymongo import MongoClient
from datetime import datetime, timezone
import json
import logging
import sys
import ema_filter
import time
import socket
import random
import struct
import pickle
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed


# Databases
IMPALA_HOST=
IMPALA_PORT=21050
MONGO_HOST='localhost:27017'
MONGO_DB='QLAD'

HOST_Graphite =  # Standard loopback interface address (localhost)
PORT = 2003




# Setup logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s: %(message)s', datefmt='%d-%m-%Y %H:%M')
ch.setFormatter(formatter)
logger.addHandler(ch)

def main():
    # Parse CLI options
    parser = OptionParser(usage="usage: %prog [options]",
                          version="%prog 1.0")
    parser.add_option("-s", "--server",
                      dest="server",
                      action="store",
                      type="string",
                      help="The server for which stats should be retrieved.",
                      metavar="STRING")
    parser.add_option("-b", "--begin",
                      dest="begin",
                      action="store",
                      type="int",
                      help="Unix timestamp defining the start of the first window.",
                      metavar="STRING")
    parser.add_option("-w", "--window",
                      dest="window",
                      action="store",
                      type="int",
                      help="Size of a window (in seconds).",
                      metavar="INT")
    parser.add_option("-t", "--threshold",
                      dest="threshold",
                      action="store",
                      type="float",
                      help="The detection threshold",
                      metavar="FLOAT")
    (options, args) = parser.parse_args()

    # Verify CLI options
    if not options.server:
        sys.stderr.write("Provide a server name.\n")
        sys.exit(-1)
    if not options.begin:
        sys.stderr.write("Provide a timestamp for the start of the first window.\n")
        sys.exit(-1)
    if not options.window:
        options.window = 60*5*1000;
        sys.stderr.write("Using the default window of 5m.\n")
    if not options.threshold:
        options.threshold = 3.0;
        sys.stderr.write("Using the default threshold of 3.\n")

    try:
       features = ['domainname', 'qtype', 'src', 'rcode', 'asn', 'country', 'res_len']
       #features = ['rcode']
       documents = []



       begin = options.begin
       end = begin + options.window
       last_ts = get_last_ts(options.server, end/1000)        #du lieu hom sau chua co se tra ve nonetype
       last_dt = datetime.fromtimestamp(last_ts/1000, tz = timezone.utc)
       while end < last_ts:
           begin_dt = datetime.fromtimestamp(begin/1000, , tz = timezone.utc)
           end_dt = datetime.fromtimestamp(end/1000, , tz = timezone.utc)            #local time of partition hdfs
           # Fetch data from impala
           logger.info("Fetching data for {} between {} and {}. Last TS in impala is {}"
                     .format(options.server, begin_dt, end_dt, last_dt))

           with ThreadPoolExecutor() as executor:
            future_to_feature = {executor.submit(process_feature, feature, begin, end, options.server, options.threshold, begin_dt, end_dt): feature for feature in features}

            for future in as_completed(future_to_feature):
                feature = future_to_feature[future]
                try:
                    result = future.result()
                    # Process the result if necessary
                except Exception as exc:
                    logger.info("f'{feature} generated an exception:")

           # Go to the next window
           begin = end
           end = begin + options.window

       print("Start next execution with --begin {}".format(begin))
    except Exception:
       logger.info("Exception raise")
       print("Start next execution with --begin {}".format(begin))
       logging.error(traceback.format_exc())
        

def process_feature(feature, begin, end, server, threshold, begin_dt, end_dt):        #begin, end: s
    histogram = fetch_data(feature, begin, end, server, begin_dt, end_dt)        #fetch using ms but this time: begin_dt, end_dt
    ent = entropy(histogram)
    anomaly = detect_anomaly(feature, ent, server, threshold)
    #store to graphite
    store_qlad_global_graphite(begin,server, feature, ent,  anomaly)            #unit of time: s

def fetch_data(feature, begin, end, server, begin_dt, end_dt):
    conn = connect(host=IMPALA_HOST, port=IMPALA_PORT, use_ssl=True)
    cur = conn.cursor()
    sql = """
SELECT {0}, count({0}) AS cnt
FROM entrada.dns
WHERE (
    (year = {1} AND month = {2} AND day = {3})
    OR (year = {4} AND month = {5} AND day = {6})
)
AND server = '{7}'
AND time >= {8}
AND time < {9}
GROUP BY {0}
""".format(
    feature,
    begin_dt.year, begin_dt.month, begin_dt.day,
    end_dt.year, end_dt.month, end_dt.day,
    server,
    begin,
    end
)            #dữ liệu tìm kiếm theo epoch time, nếu các partition của hdfs lưu theo local time thì phải chỉnh sửa lại

    logger.debug("Executing sql: " + sql)
    cur.execute(sql)
    logger.debug("Get description of results returned by impala query for feature:" + str(feature) + str(cur.description))
    output = cur.fetchall()
    logger.debug("length of output of impala query for " + feature + ":" + str(len(output)))
    conn.close()
    return output



def store_qlad_global_graphite(begin,server, feature, entropy,  anomaly):

    #x: timestamp, y: entropy,
    #histogram: full histograms, entropy -> full of this window time
    #send entropy  with begin timestamp, tag anomalies with feature
    #

    metric_path = f"test2.global."
    server = str(server).replace(".", "_")
    sock = socket.socket()
    try:
        sock.connect((HOST_Graphite, 2003))
        if anomaly:
            sock.sendall((metric_path + server + "." + str(feature) + ".abnormal" + " " + str(entropy) + " " + str(int(begin)) + "\n").encode())
            logger.debug("Sent anomalies successfully for feature: " + str(feature))
        else:
            sock.sendall((metric_path + server + "." + str(feature) + ".normal" + " " + str(entropy) + " " + str(int(begin)) + "\n").encode())

                #server: tags
                #anomaly tags

    finally:
        sock.close()

def get_last_ts(server, end_dt):
    dt = datetime.fromtimestamp(end_dt, , tz = timezone.utc)
    conn = connect(host=IMPALA_HOST, port=IMPALA_PORT, use_ssl=True)
    cur = conn.cursor()
    cur.execute("SELECT MAX(time) "
                "FROM entrada.dns "
                "WHERE server = '{0}' and year = {1} and month = {2} and day = {3} ".format(server, dt.year, dt.month, dt.day))
    logger.debug("Get last ts from impala with" + str(cur.description))
    return cur.fetchall()[0][0]




def entropy(histogram):
    """ Computes the normalized entropy of a histogram. """
    total = sum([bin[1] for bin in histogram])
    if total == 0:
        return 0.0

    entropy = 0.0
    for bin in histogram:
        if bin[1] > 0:
            entropy -= (bin[1]/total) * log10(bin[1]/total)

    # clip small negative values
    if entropy < 0:
        return 0.0
    return entropy / log10(len(histogram))







def entropy(histogram):
    """ Computes the normalized entropy of a histogram. """
    total = sum([bin[1] for bin in histogram])
    if total == 0:
        return 0.0

    entropy = 0.0
    for bin in histogram:
        if bin[1] > 0:
            entropy -= (bin[1]/total)*log10(bin[1]/total)

    # clip small negative values
    if entropy < 0:
        return 0.0
    return entropy / log10(len(histogram))


def detect_anomaly(feature, entropy, server, threshold=3):
    filter_id =  "%s_%s" % (server, feature)
    filt = ema_filter.load(filter_id)
    newEMA, newEMS = filt.update(entropy)
    filt = ema_filter.EMA(0.99, newEMA, newEMS)
    ema_filter.save(filt, filter_id)
    if filt.is_anomaly(entropy, threshold):
        return newEMS
    else:
        return None

def histogram_to_document(histogram, nb_keep=20):
    sorted_histogram = sorted(histogram, key=lambda bin: bin[1], reverse=True)
    return [{'key': bin[0], 'value': bin[1]} for bin in sorted_histogram[:nb_keep]]



def store_in_mongoDB(documents):
    if len(documents):
        client = MongoClient(host=[MONGO_HOST], username='admin', password='1111')
        db = client[MONGO_DB]
        result = db.dnsstats.insert_many(documents)
        if result:
            logger.info("Successfully saved {} windows.".format(len(documents)))
    else:
        logger.info("No new windows found.")


if __name__ == "__main__":
    main()
