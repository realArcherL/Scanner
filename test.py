#!/usr/bin/python

import threading
from queue import Queue
import time
import socket
import sys
from datetime import datetime
from tabulate import tabulate
import json
import pathlib
import os
import glob
import argparse

print_lock = threading.Lock()

json_dict={}
json_dict['scan']=[]

def reader(file_name):

    file_name = sys.argv[1]
    with open(file_name, "r+") as inputFile:
        ip_list = inputFile.read().splitlines()

    return ip_list


def logger(ips, html_file, is_last, ips_count, directory_name, child_directory):
    # individual log files : Not required Instead writing to a single json file
    # performance seems to be the same

    # logging which IP it was last on/ crashed
    with open(directory_name / "log", "w+") as log:
        log.write("Scan stopped at " + str(ips) + "the "+str(ips_count)+"th"+" line\n")


    if is_last:
        out_file_name = args.inputFileName + "_Scan.html"
        # read_files = glob.glob(sys.argv[1] + "_scan/Scans/*.txt", recursive=True)
        jsonfile = str(child_directory / out_file_name)+'.json'

        with open(jsonfile, 'w') as outfile:
            json.dump(json_dict, outfile)



def portscan(ips, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # edit socket timeout value here.
    timeout_value = 100

    s.settimeout(timeout_value)
    results = []
    try:
        con = s.connect((ips.rstrip(), port))
        with print_lock:
            service = str(socket.getservbyport(port, "tcp"))
            results.append(str(port))
            results.append(service)
            scanned_ports.append(results)
        con.close()
    except KeyboardInterrupt:
        sys.exit()
    except:
        pass


def threads():
    while True:
        worker = threads_queue.get()
        portscan(ips, worker)
        threads_queue.task_done()



    
if __name__ == '__main__':

    # Using argparse for cleaner program calling and user help
    parser = argparse.ArgumentParser(description='Port scanner')
    parser.add_argument("inputFileName",help="Input text file containing ip addresses one per line in dotted format") 
    parser.add_argument("--no_of_threads",help="No of threads",type=int,default=500)
    parser.add_argument("--ports",help="The first n ports to scan",type=int,default=1000)

    args = parser.parse_args()
    

    input_file = args.inputFileName
    num_threads = args.no_of_threads
    num_ports = args.ports

    threads_queue = Queue()
    target = reader(input_file)
    ips_count = 0
    is_last = False

    for ips in target:

        scanned_ports = []
        ips_count += 1

        # directory creation and management.

        directory_name = pathlib.Path(sys.argv[1] + "_scan")
        child_directory = pathlib.Path(sys.argv[1] + "_scan/Scans")

        # checking for the last ips
        if ips_count == len(target):
            is_last = True

        # Edit this to set number of threads # No hard-coding please.. we shall use user-input
        number_of_threads = num_threads

        for x in range(number_of_threads):
            threader = threading.Thread(target=threads)
            threader.daemon = True
            threader.start()

        start_time = time.time()
        print("Scan Started: {}".format(datetime.now().strftime('%c')))
        print("Scanning ports on IP: {}".format(ips))

        # # No hard-coding please.. we shall use user-input
        port_range = num_ports

        for worker in range(1, port_range):
            threads_queue.put(worker)
        
        threads_queue.join()
        end_time = time.time()

        # display
        table_headers = ["Ports", "Service"]
        if scanned_ports:
            print(tabulate(scanned_ports, headers=table_headers))
            print("\n")
            html_file = tabulate(scanned_ports, headers=table_headers, tablefmt="html")
            json_dict['scan'].append({'ip':ips,'result':scanned_ports})
        else:
            html_file = "<h4>Either the IP/website is down, or something is incorrect, check for the Failed files<h4>"
            print(html_file.strip("<h4>").strip("</h4>"))
            json_dict['scan'].append({'ip':ips,'result':None})
        print("Number of Ports open %s, Scan Finished in %.2f seconds\n" % (
            str(len(scanned_ports)), (end_time - start_time)))

        if directory_name.exists():
            logger(ips, html_file, is_last, ips_count, directory_name, child_directory)
        else:
            try:
                # Create target Directory
                os.mkdir(directory_name)
                os.mkdir(child_directory)
                logger(ips, html_file, is_last, ips_count, directory_name, child_directory)
                with open(directory_name / "failed_ip", "a+") as file5:
                    file5.write(ips)
            except Exception as ex:
                print(ex)

    print("Logging Complete")
    print("Generating report")
    
