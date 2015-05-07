#!/usr/bin/python
#Python Port Scanner based on Propecia.c with some improvements
#
#Shad Malloy 
#shad.malloy@securenetworkmanagement.com
#
#Version 2.0
#Enhancements: 
#Threading
#CTRL+C handling
#Randomization of Scan Addresses
#Sorted Scan output
#
#
#8/12/2014
#
#
#Imports
from threading import Thread
from netaddr import *
import signal
import datetime
import getopt
import time
import sys
import random
import os
import socket

#Globals
resultsList=[]
threadCounter = 0

#CTRL+C Handler
def customExit(signum, frame):
    #restore the original because that is what I read to prevent problems
    signal.signal(signal.SIGINT, originalSigint)
    
    #Write out any results and exit
    print "\n.xX Scan Cancelled By User Xx.\n"
    #Print results list after sorting   
    #Remove None if in list
    global rsultsList
    sortResultsList = sorted(resultsList)
    cleanResultsList = [x for x in sortResultsList if x is not None]
    if len(cleanResultsList) == 0:
        print 'No hosts found before scan cancelled'
    else:
        print 'Hosts Found Before Scan Cancelled'
        for line in sorted(cleanResultsList):
            print line
        print '\n'
    
    #End message
    print 'Scan Cancelled at ' + datetime.datetime.now().strftime('%H:%M:%S')

    #exit
    sys.exit(1)
    

#Worker Function
def scanWorker(ip,port):
    #   IPv4
    sock4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result4 = sock4.connect_ex((str(ip.ipv4()),int(port)))
    if result4 == 0:
        resultsList.append(str(ip) + ":" + port + " Open")
    sock4.close()
    
    #   IPv6
    ip6Working = IPAddress(ip).ipv6()
    sock6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    result6 = sock6.connect_ex((str(ip6Working),int(port),0,0))
    if result6 == 0:
        resultsList.append(str(ip6Working) + ":" + port + " Open")
    sock6.close()
    
    #Update thread counter
    global threadCounter 
    threadCounter -= 1

#Main
def main(argv):
    scanRange = '127.0.0.1/32'
    scanPort = '443'
    usage = 'usage pypecia.py -p <port> -r <CIDR range> -t <number of threads *default is 256 **setting greater than 256 can cause errors in python>'
    threadMax = 256
    
    #Set socket timeout to 250 ms. This should be sufficient. If needed this can be increased 350ms should 
    #be sufficient for servers located in Asia when scanning from North America. For no timeout use None
    socket.setdefaulttimeout(.25)
   
    try:
        opts, args = getopt.getopt(sys.argv[1:],"hp:r:t:",["help","scanPort=","scanRange=","threads="])
    except getopt.GetoptError:
        print usage

    for opt,arg in opts:
        if opt in ('-h', "--help"):
            print usage
            sys.exit()
        elif opt in ("-p", "--port"):
            scanPort = arg
        elif opt in ("-r", "--range"):
            scanRange = arg
        elif opt in ("-t", "--threads"):
            threadMax = arg
        else:
            assert False, "Option not recognized: try -h for usage"
            
    #Sanity Check for threadMax
    if IPNetwork(scanRange).size < threadMax:
        threadMax = IPNetwork(scanRange).size
            
    #create the randomized scan list
    ipList = list(IPNetwork(scanRange))
    random.shuffle(ipList)
    
    #Start message
    print 'Scan Started at ' + datetime.datetime.now().strftime('%H:%M:%S')
    
    for ip in ipList:
        
        #update thread counter
        global threadCounter
        threadCounter += 1
        
        #wait if thread count is more than maximum thread count
        while int(threadCounter) >= int(threadMax):
            time.sleep(.25)
               
        #Do work
        else:
            #Actual Work
            worker = Thread(target=scanWorker, args=(ip,scanPort,))
            worker.setDaemon(True)
            worker.start()
            
    #Reset socket timeout to default value
    socket.setdefaulttimeout(None)
    
    #Print results list after sorting   
    #Remove None if in list
    sortResultsList = sorted(resultsList)
    cleanResultsList = [x for x in sortResultsList if x is not None]
    if len(cleanResultsList) == 0:
        print 'No hosts found with port ' + scanPort + ' in ' + scanRange
    else:
        for line in sorted(cleanResultsList):
            print line
    
    #End message
    print 'Scan Complete at ' + datetime.datetime.now().strftime('%H:%M:%S')
    
    #Browser hint for HTTP(S)
    if int(scanPort) is 443:
        print 'To connect using a browser enclose address in brackets. https://[::ffff:192.168.0.1]'
    elif int(scanPort) is 80:
        print 'To connect using a browser enclose address in brackets. http://[::ffff:192.168.0.1]'

if __name__ == "__main__":
    #store original SIGINT handler
    originalSigint = signal.getsignal(signal.SIGINT)
    #use custom CTRL+C handler
    signal.signal(signal.SIGINT, customExit)
    #call main
    main(sys.argv[1:])
