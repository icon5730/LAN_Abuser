A Bash script designed to scan and attack different targets on your own LAN in order to test your SIEM monitoring and response.

The script performs the following operations:
- Detects the user's system's network interfaces and gives the user the option to choose the interface they want to use.
- Gives the user a choice between a Fast Nmap scan, a full scan (all ports +UDP) and a vulnerability scan (service detection + vuln script).
- Scans all endpoints on the local network based on the scan. Scanning data is saved inside /var/log in all file formats available for Nmap.
- Gives the user the choice to either attack an IP address from a lits of scanned targets, or have the script select a random target.
- Gives the user a choice between a Brute Force attack, Man-in-the-Middle (MITM) attack, a Denial-of-Service (DoS) attack, or have the script select a random attack
- Attacks and their results are saved in /tmp.
- The user can repeat the attack, choose a different attack, change targets, or conclude and exit.
- All scanning and attack data is saved inside /var/log/attack_log.txt
- If the user chooses to exit, the script gives the option of creating a timestamped folder and gathering all the logs and attack results for convenience.
- If the user chooses to create a folder, an html file is produced out of the .xml Nmap scan file to make the scan results more presentable.

Notes: The script was tested on Metasploitable and Windows Server 2019 VM's as a proof of concept.

<b>Full Script Run:</b>

![1](https://github.com/user-attachments/assets/c68abb33-cf88-4376-b28c-1fc289796b52)
![2](https://github.com/user-attachments/assets/796bc1a5-79dd-4ecb-a25e-260086196ac8)
![3](https://github.com/user-attachments/assets/315c31c3-60ee-4244-bbac-f5cafa4e5f19)
![4](https://github.com/user-attachments/assets/91365556-88c5-4cc8-9b20-930e8ae98be6)

<b>Generated Folder:</b>

![5](https://github.com/user-attachments/assets/72d66c12-55b3-4e5d-9bba-f334a5292ba5)

<b>Log Examples:</b>

![6](https://github.com/user-attachments/assets/026f2fb2-d5e9-4efb-85f5-77799b200cca)
![7](https://github.com/user-attachments/assets/503175e8-3435-4a99-ae83-7495d36cb068)

<b>Man-in-the-Middle attack .pcap Result Example:</b>

![8](https://github.com/user-attachments/assets/3a52bd33-6b1e-4b0d-badb-a411cb806f2d)
