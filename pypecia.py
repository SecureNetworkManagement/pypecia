#!/usr/bin/python
#Python Port Scanner based on Propecia.c with some improvements
#
#Shad Malloy 
#shad.malloy@securenetworkmanagement.com
#
#
# Version 2.1
# Added option to load scan addresses from file
#2/28/18
#
#Version 2.0
#Enhancements: 
#Threading
#CTRL+C handling
#Randomization of Scan Addresses
#Sorted Scan output
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
		print 'No hosts found before scan canceled'
	else:
		print 'Hosts Found Before Scan Canceled'
		for line in sorted(cleanResultsList):
				print line
		print '\n'
    
	#End message
	print 'Scan Canceled at ' + datetime.datetime.now().strftime('%H:%M:%S')

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
	usage = 'usage pypecia.py -p <port> -r <CIDR range> -f <File with CIDR ranges> -o <output file> -t <number of threads> \n*default is 256 \n**Use ulimit -n to determine the maximum number>'
	threadMax = 256
	outFileFlag= False
	
   #Create working list
	ipListTemp=[] 
	
	#Set socket timeout to 250 ms. This should be sufficient. If needed this can be increased 350ms should 
	#be sufficient for servers located in Asia when scanning from North America. For no timeout use None
	socket.setdefaulttimeout(.25)
   
	try:
		opts, args = getopt.getopt(sys.argv[1:],"hp:r:t:f:o:",["help","scanPort=","scanRange=","threads=","file=","output="])
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
			ipListTemp.append([arg])
		elif opt in ("-f", "--file"):
			scanFile = arg
			if os.path.exists(arg):
				ipFile = open(arg, 'r')
				for line in ipFile:
					ipListTemp.append([line])
				ipFile.close()
			else:
				print('### Path Not Found ... Exiting ###')
				sys.exit(1)
		elif opt in ("-t", "--threads"):
			threadMax = arg
		elif opt in ("-o", "--output"):
			outputFile = arg
			outFileFlag  = True
			if os.path.exists(arg):
				print('=== Output File Exists, Opening for Append ===')
				outFile = open(arg, 'a')
			else:
				outFile = open(arg, 'w')
		else:
			assert False, "Option not recognized: try -h for usage"

	#Create the IP List
	workingIPList = []
	for line in ipListTemp:
		line = str(line).strip('[]\'\\n')
		if len(line) != 0:
			for ip in IPNetwork(line).iter_hosts():
				workingIPList.append(ip)    
    
	#Sanity Check for threadMax
	if len(workingIPList) < threadMax:
		threadMax = len(workingIPList)
		print('Setting threads equal to number of hosts: ' + str(threadMax))
            
	#create the randomized scan list
	random.shuffle(workingIPList)
    
	#Start message
	print 'Scan Started at ' + datetime.datetime.now().strftime('%H:%M:%S')
    
	for ip in workingIPList:
        
		#update thread counter
		global threadCounter
		threadCounter += 1
        
		#wait if thread count is more than maximum thread count
		while int(threadCounter) >= int(threadMax):
				time.sleep(.1)
               
		#Do work
		else:
				#Actual Work
				worker = Thread(target=scanWorker, args=(ip,scanPort,))
				worker.start()
				worker.join(.05)
            
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
				if outFileFlag == True:
					outFile.write(line + '\n')
	
	#Close Output File
	outFile.close()
    
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
