The script works with following command and was explicitly built on python3 platform:

usage: test.py [-h] [--no_of_threads NO_OF_THREADS] [--ports PORTS] inputFileName


Two folders get made for each input list the user provides, parent directory and child directory, along with a log file, which stores the index when the script failed, this helps to ensure to start the script back from where it failed. 

TO-DO :  We need to take care of this automatically

This has to be done manyally since the code doesn't know how to do it, itself. As in the user will have to manually remove the IP addresses from the earlier provided list till the index, shown in the file.

Ex. scenario: "<input_file_name>_scans", Parent folder, "Scans", Child Folder. 


Once the code has finished execution, a HTML file and JSON file are ouput. 

The script was coded with performance in mind, and hence number of threads, timeout time and number of ports to be scanned weren't explicitly declared, instead the user can change these, by passing them as parameters to the program.

For best scan results, use atleast 500 Threads, with timeout time as 60 seconds and port range till 3072. This is almost equivalent to -T4 scan in nmap, (scan optimizations are yet another area to improve the code upon.)


