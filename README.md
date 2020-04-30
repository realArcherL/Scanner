The script works with following command and was explicitly built on python3 platform:

ex: python3 <input_file name>

Two folders get made for each input list the user provides, parent directory and child directory, along with a log file, which stores the index when the script failed, this helps to ensure to start the script back from where it failed. This has to be done manyally since the code doesn't know how to do it, itself. As in the user will have to manually remove the IP addresses from the earlier provided list till the index, shown in the file.

Ex. scenerio: "<input_file_name>_scans", Parent folder, "Scans", Child Folder. Each scan result of the ouput is stored in a html code format in a .txt file individually and once the code has finished execution, all the html files are converted to an HTML file. (This was done to avoid read, write power conditions). more imporvements are to be done, to automate the process of deletion.

The script was coded with performace in mind, and hence number of threads, timeout time and number of ports to be scanned weren't explicitly declared, instead the user can change these, by editing the code. (variables are higlighted in the code).

For best scan results, use atleast 500 Threads, with timeout time as 60 seconds and port range till 3072. This is almost equivalent to -T4 scan in nmap, (scan optimizations are yet another area to improve the code upon.)
