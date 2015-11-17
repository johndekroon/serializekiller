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

from datetime import datetime

parser = argparse.ArgumentParser(prog='serializekiller.py', formatter_class=argparse.RawDescriptionHelpFormatter, description="""SerializeKiller.
    Usage:
    ./serializekiller.py targets.txt
    Or:
    ./serializekiller.py --url example.com
""")
parser.add_argument('--url', nargs='?', help="Scan a single URL")
parser.add_argument('file', nargs='?', help='File with targets')
args = parser.parse_args()

def nmap(url, retry = False, *args):
    global num_threads
    global shellCounter
    global threads

    num_threads +=1
    found = False
    cmd = 'nmap --open -p 5005,8080,9080,8880,7001,7002,16200 '+url
    print "Scanning: "+url
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        out, err = p.communicate()
        if "5005" in out:
            if(websphere(url, "5005")):
                found = True
        if "8880" in out:
            if(websphere(url, "8880")):
                found = True
        if "7001" in out:
            if(weblogic(url, 7001)):
                found = True
        if "16200" in out:
            if(weblogic(url, 16200)):
                found = True
        if "8080" in out:
            if(jenkins(url, 8080)):
                found = True
        if "9080" in out:
            if(jenkins(url, 9080)):
                found = True
        if(found):
            shellCounter +=1
        num_threads -=1
    except Exception:
        num_threads -=1
        threads -= 1
        time.sleep(5)
        if(retry):
            print " ! Unable to scan this host "+url
        else:
            nmap(url, True)

def websphere(url, port, retry = False):
    try:
        cmd = 'curl -m 10 --insecure https://'+url+":"+port
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        out, err = p.communicate()
        if "rO0AB" in out:
            print " - Vulnerable Websphere: "+url+" ("+port+")"
            return True
        
        cmd = 'curl -m 10 http://'+url+":"+port
        with open(os.devnull, 'w') as fp:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        out, err = p.communicate()
        if "rO0AB" in out:
            print " - Vulnerable Websphere: "+url+" ("+port+")"
            return True
    except:
        time.sleep(3)
        if(retry):
            print " ! Unable to verify Websphere vulnerablity for host "+url+":"+str(port)
            return False
        return websphere(url, port, True)

#Used this part from https://github.com/foxglovesec/JavaUnserializeExploits
def weblogic(url, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
        server_address = (url, port)
        sock.connect(server_address)
        
        # Send headers
        headers='t3 12.2.1\nAS:255\nHL:19\nMS:10000000\nPU:t3://us-l-breens:7001\n\n'
        sock.sendall(headers)
        data = sock.recv(1024)
        sock.close()
        if "HELO" in data:
            print " - Vulnerable Weblogic: "+url+" ("+str(port)+")"
            return True
        return False
    except:
        print " ! Unable to verify Weblogic vulnerability for host "+url+":"+str(port)

#Used this part from https://github.com/foxglovesec/JavaUnserializeExploits
def jenkins(url, port, suffix = ""):
    try:
        #Query Jenkins over HTTP to find what port the CLI listener is on
        r = requests.get('http://'+url+':'+str(port)+suffix)
        if 'X-Jenkins-CLI-Port' in r.headers:
            cli_port = int(r.headers['X-Jenkins-CLI-Port'])
        elif suffix == "":
            return jenkins(url, port, "/jenkins/")
        else:
            return False
    except:
        #could not connect to the server
        return False
    
    #Open a socket to the CLI port
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (url, cli_port)
    sock.connect(server_address)
    
    # Send headers
    headers='\x00\x14\x50\x72\x6f\x74\x6f\x63\x6f\x6c\x3a\x43\x4c\x49\x2d\x63\x6f\x6e\x6e\x65\x63\x74'
    sock.send(headers)
    
    data1 = sock.recv(1024)
    data2 = sock.recv(1024)
    if "rO0AB" in data2:
        print " - Vulnerable Jenkins: "+url+":"+str(port)+suffix
        return True
    return False

def dispatch(url):
    try:
        threading.Thread(target=nmap, args=(url, False, 1)).start()
    except:
        print " ! Unable to start thread. Waiting..."
        time.sleep(2)
        threads -= 2
        dispatch(url)

def urlStripper(url):
    url = str(url.replace("\r", ''))
    url = str(url.replace("\n", '')) 
    url = str(url.replace("/", ''))
    url = str(url.replace("https://", ''))
    url = str(url.replace("http://", ''))
    return url

def worker():
    with open(args.file) as f:
        content = f.readlines()
        for url in content:
            while((num_threads > threads)):
                time.sleep(1)
            url = urlStripper(url)
            dispatch(url)
        while(num_threads > 1):
            time.sleep(1)

        print "\r\n => scan done. "+str(shellCounter)+" vulnerable hosts found."
        print "Execution time: "+str(datetime.now() - startTime)
        exit()

if __name__ == '__main__':
    startTime = datetime.now()  
    print "Start SerializeKiller..."
    print "This could take a while. Be patient.\r\n"
    num_threads = 0
    if(args.url):
        nmap(urlStripper(args.url))
    elif(args.file):
        num_threads = 0
        threads = 35
        shellCounter = 0
        t = threading.Thread(target=worker).start()
    else:
        print "ERROR: Specify a file or a url!"