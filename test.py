#!/usr/bin/python

import threading
from queue import Queue
import time
import socket
import sys
from datetime import datetime
from tabulate import tabulate
import pathlib
import os
import glob

print_lock = threading.Lock()


# ip = socket.gethostbyname(target)
# out_file_name = sys.argv[1] + "_Scan.html"


def reader():
    file_name = sys.argv[1]
    with open(file_name, "r+") as inputFile:
        ip_list = inputFile.read().splitlines()

    return ip_list


def logger(ips, html_file, is_last, ips_count, directory_name, child_directory):
    # individual log files
    file_name = str(ips_count) + "_scan_log.txt"
    file1 = open(child_directory / file_name, "a+")
    title = "<body><h3>Scan result for {}: </h3></body>".format(ips)
    file1.write(title)
    file1.write(html_file)
    file1.write("<br><br>")
    file1.close()

    # logging which IP it was last on/ crashed
    with open(directory_name / "log", "w+") as log:
        log.write(str(ips_count))

    if is_last:
        out_file_name = sys.argv[1] + "_Scan.html"
        read_files = glob.glob("*.txt")

        with open(child_directory / out_file_name, "wb") as outfile:
            for f in read_files:
                with open(f, "rb") as infile:
                    outfile.write(infile.read())


def portscan(ips, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    timeout_value = 20
    s.settimeout(timeout_value)
    results = []
    try:
        con = s.connect((ips, port))
        with print_lock:
            service = str(socket.getservbyport(port, "tcp"))
            results.append(port)
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
    threads_queue = Queue()
    target = reader()
    ips_count = 0
    is_last = False

    for ips in target:

        scanned_ports = []

        # checking for the last ips
        if ips_count == len(target):
            is_last = True

        # Edit this to set number of threads
        number_of_threads = 500

        for x in range(number_of_threads):
            threader = threading.Thread(target=threads)
            threader.daemon = True
            threader.start()

        start_time = time.time()
        print("Scan Started: {}".format(datetime.now().strftime('%c')))
        print("Scanning ports on IP: {}".format(ips))

        # Edit this to change the range of the ports to be scanner, total 1-65534
        port_range = 1024

        for worker in range(1, port_range):
            threads_queue.put(worker)

        threads_queue.join()
        end_time = time.time()

        # display
        table_headers = ["Ports", "Service"]
        print(tabulate(scanned_ports, headers=table_headers))
        print("\n")
        print("Number of Ports open %s, Scan Finished in %.2f seconds\n" % (
            str(len(scanned_ports)), (end_time - start_time)))

        html_file = tabulate(scanned_ports, headers=table_headers, tablefmt="html")

        # directory creation and management.
        directory_name = pathlib.Path("Temp")
        child_directory = pathlib.Path("Temp/Scans")

        if directory_name.exists():
            logger(ips, html_file, is_last, ips_count, directory_name, child_directory)
        else:
            try:
                # Create target Directory
                os.mkdir(directory_name)
                os.mkdir(child_directory)
                print("Directory ", directory_name, " Created ")
                logger(ips, html_file, is_last, ips_count, directory_name, child_directory)
            except Exception as ex:
                print(ex)
    print("Logging Complete")
    print("Generating report")
