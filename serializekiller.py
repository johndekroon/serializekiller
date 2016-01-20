#!/usr/bin/env python
# ------------------------------------------------------------------------------
# Name:        SerializeKiller
# Purpose:     Finding vulnerable java servers
#
# Author:      (c) John de Kroon, 2015
# Version:     1.0.2
# ------------------------------------------------------------------------------

import subprocess
import threading
import time
import socket
import sys
import argparse
import requests
import re

from socket import error as socket_error
from datetime import datetime

parser = argparse.ArgumentParser(prog='serializekiller.py',
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 description="Scan for Java Deserialization vulnerability.")
parser.add_argument('--url', nargs='?', help="Scan a single URL")
parser.add_argument('file', nargs='?', help='File with targets')
args = parser.parse_args()


def nmap(host, *args):
    global shellCounter
    global threads
    global target_list

    # All ports to enumerate over for jboss, jenkins, weblogic, websphere
    port_list = ['80', '81', '443', '444', '1099', '5005',
                '7001', '7002', '8080', '8081', '8083', '8443',
                 '8880', '8888', '9000', '9080', '9443', '16200']

    # Are there any ports defined for this host?
    if not target_list[host]:
        found = False
        cmd = 'nmap --host-timeout 5 --open -p %s %s' % (','.join(port_list), host)
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            out, err = p.communicate()

            for this_port in port_list:
                if websphere(host, this_port) or weblogic(host, this_port) or jboss(host, this_port) or jenkins(host, this_port):
                    found = True
            if found:
                shellCounter += 1
        except ValueError, v:
            print " ! Something went wrong on host: %s: %s" % (host, v)
            return
    else:
        for port in target_list[host]:
            if websphere(host, port) or weblogic(host, port) or jenkins(host, port) or jboss(host, port):
                shellCounter += 1
        return


def websphere(url, port, retry=False):
    try:
        output = requests.get('https://'+url+":"+port, timeout=8)
        if "rO0AB" in output:
            print " - (possibly) Vulnerable Websphere: "+url+" ("+port+")"
            return True
    except requests.exceptions.HTTPError, e:
        if e.getcode() == 500:
            if "rO0AB" in e.read():
                print " - (possibly) Vulnerable Websphere: "+url+" ("+port+")"
                return True
    except:
        pass

    try:
        output = requests.get('http://'+url+":"+port, timeout=3)
        if "rO0AB" in output:
            print " - (possibly) Vulnerable Websphere: "+url+" ("+port+")"
            return True
    except requests.exceptions.HTTPError, e:
        if e.getcode() == 500:
            if "rO0AB" in e.read():
                print " - (possibly) Vulnerable Websphere: "+url+" ("+port+")"
                return True
    except:
        pass


# Used this part from https://github.com/foxglovesec/JavaUnserializeExploits
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
            print "[debug] Received weblogic data:", data
        except socket.timeout:
            return False

        sock.close()
        if "HELO" in data:
            # CGP: https://github.com/nmap/nmap/blob/master/scripts/weblogic-t3-info.nse
            # weblogic_version = string.match(result, "^HELO:(%d+%.%d+%.%d+%.%d+)%.")
            if weblogic_vulnerable(data):
                print " - Vulnerable Weblogic: "+url+" ("+str(port)+")"
                return True
            else:
                return False
        else:
            return False
    except socket_error:
        return False

def weblogic_vulnerable(data):
    # Very cheap hack
    affected_versions = ['10.3.6.0', '12.1.2.0', '12.1.3.0', '12.2.1.0']
    m = re.findall(r"[0-9]+(?:\.[0-9]+){3}", data)[0]
    print "[debug] Found Weblogic version:", m
    if m in affected_versions:
        return True

    return False


# Used something from https://github.com/foxglovesec/JavaUnserializeExploits
def jenkins(url, port):
    # CGP: Check the Jenkins Remote API here:
    # https://wiki.jenkins-ci.org/display/JENKINS/Remote+access+API
    JENKINS_FIRST_PATCHED_VERSION = 1.638
    try:
        cli_port = False
        try:
            output = requests.get('https://'+url+':'+port+"/jenkins/", timeout=8)

            # Perform version detection before anything else
            jenkins_version = float(output.headers['X-Jenkins'])
            if jenkins_version >= JENKINS_FIRST_PATCHED_VERSION:
                print "[DEBUG] Patched version of Jenkins (%.3f). Moving on..." % jenkins_version
                return False

            cli_port = int(output['X-Jenkins-CLI-Port'])
        except requests.exceptions.HTTPError, e:
            if e.getcode() == 404:
                try:
                    output = requests.get('https://'+url+':'+port, timeout=8)
                    cli_port = int(output.headers['X-Jenkins-CLI-Port'])
                except:
                    pass
        except:
            pass
    except:
        print " ! Could not check Jenkins on https. Maybe your SSL lib is broken."
        pass

    if not cli_port:
        try:
            output = requests.get('http://'+url+':'+port+"/jenkins/", timeout=8)
            cli_port = int(output.headers['X-Jenkins-CLI-Port'])
        except requests.exceptions.HTTPError, e:
            if e.getcode() == 404:
                try:
                    output = requests.get('http://'+url+':'+port, timeout=8).info()
                    cli_port = int(output.headers['X-Jenkins-CLI-Port'])
                except:
                    return False
        except:
            return False

    # Open a socket to the CLI port
    try:
        server_address = (url, cli_port)
        sock = socket.create_connection(server_address, 5)

        # Send headers
        headers = '\x00\x14\x50\x72\x6f\x74\x6f\x63\x6f\x6c\x3a\x43\x4c\x49\x2d\x63\x6f\x6e\x6e\x65\x63\x74'
        sock.send(headers)

        data1 = sock.recv(1024)
        if "rO0AB" in data1:
            print " - Vulnerable Jenkins: "+url+" ("+str(port)+")"
            return True
        else:
            data2 = sock.recv(1024)
            if "rO0AB" in data2:
                print " - Vulnerable Jenkins: "+url+" ("+str(port)+")"
                return True
    except:
        pass
    return False


def jboss(url, port, retry=False):
    try:
        output = requests.get('https://'+url+':'+port+"/invoker/JMXInvokerServlet", timeout=8)
    except:
        try:
            output = requests.get('http://'+url+':'+port+"/invoker/JMXInvokerServlet", timeout=8)
        except:
            # OK. I give up.
            return False

    if "\xac\xed\x00\x05" in output:
        print " - Vulnerable JBOSS: "+url+" ("+port+")"
        return True
    return False


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

    for line in content:
        if ":" in line:
            item = line.strip().split(':')
            if item[0] not in target_list:
                target_list[item[0]] = [item[1]]
            else:
                target_list[item[0]].append(item[1])
        else:
            if line.strip() not in target_list:
                target_list[line.strip()] = []

    print str(len(target_list)) + " targets found."
    total_jobs = len(target_list)
    current = 0

    for host in target_list:
        current += 1
        while threading.active_count() > threads:
            print " ! We have more threads running than allowed. Current: {} Max: {}.".format(threading.active_count(), threads)
            if threads < 100:
                threads += 1
            sys.stdout.flush()
            time.sleep(2)
        print " # Starting test {} of {} on {}.".format(current, total_jobs, host)
        sys.stdout.flush()
        threading.Thread(target=nmap, args=(host, False, 1)).start()

    # We're done!
    while threading.active_count() > 2:
        print " # Waiting for everybody to come back. Still {} active.".format(threading.active_count() - 1)
        sys.stdout.flush()
        time.sleep(4)

    print
    print " => Scan done. "+str(shellCounter)+" vulnerable hosts found."
    print "Execution time: "+str(datetime.now() - startTime)
    exit()

if __name__ == '__main__':
    startTime = datetime.now()
    print "Start SerializeKiller..."
    print "This could take a while. Be patient."
    print

    target_list = {}
    shellCounter = 0
    if args.url:
        target_list[urlStripper(args.url)] = []
        nmap(urlStripper(args.url))
    elif args.file:
        threads = 30
        worker()
    else:
        print "ERROR: Specify a file or a url!"
