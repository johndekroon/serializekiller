#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:        SerializeKiller
# Purpose:     Finding vulnerable vulnerable servers
#
# Author:      (c) John de Kroon, 2015
# Version:     1.0.1
#-------------------------------------------------------------------------------

import subprocess
import threading
import time
import socket
import sys
import argparse
import urllib2
import ssl

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
                if jenkins(host, "8080"):
                    found = True
                if jboss(host, 8080):
                    found = True
            if "9080" in out:
                if jenkins(host, "9080"):
                    found = True
            if found:
                shellCounter += 1
        except ValueError:
            print " ! Something went wrong on host: "+host
            return
    else:
        for port in target_list[host]:
            if websphere(host, port) or weblogic(host, port) or jenkins(host, port) or jboss(host, port):
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


#Used something from https://github.com/foxglovesec/JavaUnserializeExploits
def jenkins(url, port):
    cli_port = False
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        output = urllib2.urlopen('https://'+url+':'+port+"/jenkins/", context=ctx, timeout=8).info()
        cli_port =  int(output['X-Jenkins-CLI-Port'])
    except urllib2.HTTPError, e:
        if e.getcode() == 404:
            try:
                output = urllib2.urlopen('https://'+url+':'+port, context=ctx, timeout=8).info()
                cli_port =  int(output['X-Jenkins-CLI-Port'])
            except:
                pass
    except:
        pass
    
    if cli_port == False:
        try:
            output = urllib2.urlopen('http://'+url+':'+port+"/jenkins/", timeout=8).info()
            cli_port =  int(output['X-Jenkins-CLI-Port'])
        except urllib2.HTTPError, e:
            if e.getcode() == 404:
                try:
                    output = urllib2.urlopen('http://'+url+':'+port, timeout=8).info()
                    cli_port =  int(output['X-Jenkins-CLI-Port'])
                except:
                    return False
        except:
            return False
    
    #Open a socket to the CLI port
    try:
        server_address = (url, cli_port)
        sock = socket.create_connection(server_address, 5)
        
        # Send headers
        headers = '\x00\x14\x50\x72\x6f\x74\x6f\x63\x6f\x6c\x3a\x43\x4c\x49\x2d\x63\x6f\x6e\x6e\x65\x63\x74'
        sock.send(headers)

        data1 =sock.recv(1024)
        if "rO0AB" in data1:
            print " - Vulnerable Jenkins: "+url+":"+str(port)
            return True
        else:
            data2 = sock.recv(1024)
            if "rO0AB" in data2:
                print " - Vulnerable Jenkins: "+url+":"+str(port)
                return True
    except:
        pass
    return False

def jboss(url, port, retry = False):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        output = urllib2.urlopen('https://'+url+':'+port+"/invoker/JMXInvokerServlet", context=ctx, timeout=8).read()
    except:
        try:
            output = urllib2.urlopen('http://'+url+':'+port+"/invoker/JMXInvokerServlet", timeout=8).read()
        except:
            #OK. I give up.
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
            print " ! We have more threads running than allowed. Current: {} Max: {}.".format(threading.active_count(),
                                                                                           threads)
            if threads < 100:
                threads+=1
            sys.stdout.flush()
            time.sleep(2)
        print " # Starting test {} of {} on {}.".format(current, total_jobs, host)
        sys.stdout.flush()
        threading.Thread(target=nmap, args=(host, False, 1)).start()

    #we're done!
    while threading.active_count() > 2:
        print " # Waiting for everybody to come back. Still {} active.".format(threading.active_count() - 1)
        sys.stdout.flush()
        time.sleep(4)

    print
    print " => scan done. "+str(shellCounter)+" vulnerable hosts found."
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
