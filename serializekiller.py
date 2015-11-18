#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:        SerializeKiller
# Purpose:     Finding vulnerable vulnerable servers
#
# Author:      (c) John de Kroon, 2015
#-------------------------------------------------------------------------------

import os
import subprocess
import json
import threading
import time
import socket
import sys
import argparse
import requests
import base64
import urllib2
import httplib2
import httplib
import ssl

from requests.exceptions import ConnectionError
from socket import error as socket_error
from datetime import datetime

parser = argparse.ArgumentParser(prog='serializekiller.py',
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 description="Scan for Java Deserialization vulnerability.")
parser.add_argument('--url', nargs='?', help="Scan a single URL")
parser.add_argument('file', nargs='?', help='File with targets')
parser.add_argument('portfile', nargs='?', help='File with targets and ports.')
args = parser.parse_args()


def nmap(host, *args):
    global shellCounter
    global threads
    global target_list

    # are there any ports defined for this host?
    if not target_list[host]:
        found = False
        cmd = 'nmap --host-timeout 5 --open -p 5005,8080,9080,8880,7001,7002,16200 '+host
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            out, err = p.communicate()
            if "5005" in out:
                if websphere(host, "5005"):
                    found = True
            if "8880" in out:
                if websphere(host, "8880"):
                    found = True
            if "7001" in out:
                if weblogic(host, 7001):
                    found = True
            if "16200" in out:
                if weblogic(host, 16200):
                    found = True
            if "8080" in out:
                if jenkins(host, 8080):
                    found = True
            if "9080" in out:
                if jenkins(host, 9080):
                    found = True
            if found:
                shellCounter += 1
        except ValueError:
            print "Something went wrong on host: "+host
            return
    else:
        for port in target_list[host]:
            if websphere(host, port) or weblogic(host, port) or jenkins(host, port):
                shellCounter += 1
        return

def websphere(url, port, retry=False):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        output = urllib2.urlopen('https://'+url+":"+port, context=ctx, timeout=8).read()
        if "rO0AB" in output:
            print " - Vulnerable Websphere: "+url+" ("+port+")"
            return True
    except urllib2.HTTPError, e:
        if e.getcode() == 500:
            if "rO0AB" in e.read():
                print " - Vulnerable Websphere: "+url+" ("+port+")"
                return True
    except:
        pass

    try:
        output = urllib2.urlopen('http://'+url+":"+port, timeout=3).read()
        if "rO0AB" in output:
            print " - Vulnerable Websphere: "+url+" ("+port+")"
            return True
    except urllib2.HTTPError, e:
        if e.getcode() == 500:
            if "rO0AB" in e.read():
                print " - Vulnerable Websphere: "+url+" ("+port+")"
                return True
    except:
        pass
    
#Used this part from https://github.com/foxglovesec/JavaUnserializeExploits
def weblogic(url, port):
    try:
        server_address = (url, int(port))
        sock = socket.create_connection(server_address, 4)
        sock.settimeout(2)
        # Send headers
        headers = 't3 12.2.1\nAS:255\nHL:19\nMS:10000000\nPU:t3://us-l-breens:7001\n\n'
        sock.sendall(headers)

        try:
            data = sock.recv(1024)
        except socket.timeout:
            return False

        sock.close()
        if "HELO" in data:
            print " - Vulnerable Weblogic: "+url+" ("+str(port)+")"
            return True
        return False
    except socket_error:
        return False


#Used this part from https://github.com/foxglovesec/JavaUnserializeExploits
def jenkins(url, port, suffix=""):
    try:
        #Query Jenkins over HTTP to find what port the CLI listener is on
        r = requests.get('http://'+url+':'+str(port)+suffix)
        if 'X-Jenkins-CLI-Port' in r.headers:
            cli_port = int(r.headers['X-Jenkins-CLI-Port'])
        elif suffix == "":
            return jenkins(url, port, "/jenkins/")
        else:
            return False
    except ConnectionError:
        #could not connect to the server
        return False

    #Open a socket to the CLI port
    server_address = (url, cli_port)
    sock = socket.create_connection(server_address, 4)
    sock.settimeout(2)
    
    # Send headers
    headers = '\x00\x14\x50\x72\x6f\x74\x6f\x63\x6f\x6c\x3a\x43\x4c\x49\x2d\x63\x6f\x6e\x6e\x65\x63\x74'
    sock.send(headers)
    
    try:
        sock.recv(1024)
        data2 = sock.recv(1024)
    except socket.timeout:
        return False

    if "rO0AB" in data2:
        print " - Vulnerable Jenkins: "+url+":"+str(port)+suffix
        return True
    return False

def jboss(url, port, retry = False):
    try:
        cmd = 'curl -m 10 --insecure https://'+url+":"+port+"/invoker/JMXInvokerServlet"
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        out, err = p.communicate()
        if "\xac\xed\x00\x05" in out:
            print " - Vulnerable JBOSS: "+url+" ("+port+")"
            return True
    except:
        time.sleep(3)
        if retry:
            print " ! Unable to verify JBOSS vulnerablity for host "+url+":"+str(port)
            return False
        return websphere(url, port, True)

def urlStripper(url):
    url = str(url.replace("https:", ''))
    url = str(url.replace("http:", ''))
    url = str(url.replace("\r", ''))
    url = str(url.replace("\n", '')) 
    url = str(url.replace("/", ''))
    return url


def read_file(filename):
    f = open(filename)
    content = f.readlines()
    f.close()
    return content


def worker():
    global threads
    content = read_file(args.file)
    
    if args.portfile:
        hostport = read_file(args.portfile)
        for line in hostport:
            item = line.strip().split(':')
        if item[0] not in target_list:
            target_list[item[0]] = (item[1])
        else:
            target_list[item[0]].append(item[1])

    for line in content:
        target_list[line.strip()] = []

    print str(len(target_list)) + " targets found."

    total_jobs = len(target_list)
    current = 0

    for host in target_list:
        current += 1
        while threading.active_count() > threads:
            print "We have more threads running than allowed. Current: {} Max: {}.".format(threading.active_count(),
                                                                                           threads)
            if threads < 100:
                threads+=1
            sys.stdout.flush()
            time.sleep(2)
        print "Starting test {} of {} on {}.".format(current, total_jobs, host)
        sys.stdout.flush()
        threading.Thread(target=nmap, args=(host, False, 1)).start()

    #we're done!
    while threading.active_count() > 2:
        print "Waiting for everybody to come back. Still {} active.".format(threading.active_count() - 1)
        sys.stdout.flush()
        time.sleep(4)

    print
    print " => scan done. "+str(shellCounter)+" vulnerable hosts found."
    print "Execution time: "+str(datetime.now() - startTime)

if __name__ == '__main__':
    startTime = datetime.now()
    print "Start SerializeKiller..."
    print "This could take a while. Be patient."
    print

    target_list = {}
    if args.url:
        nmap(urlStripper(args.url))
    elif args.file:
        threads = 30
        shellCounter = 0
        worker()
    else:
        print "ERROR: Specify a file or a url!"
