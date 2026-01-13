#!/bin/bash

# SubARG - Subdomain Enumeration Automation Tool
# Author: Argha Dey (Mr. Ghost)

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'
ITALIC='\033[3m'

# Variables
DOMAIN=""
DOMAIN_LIST=""
OUTPUT_FILE=""
OUTPUT_FORMAT="txt"
TOOLS_DIR="$HOME/tools"
WORDLIST_DIR="$TOOLS_DIR/wordlists"
WORDLIST="$WORDLIST_DIR/subdomains.txt"
TEMP_DIR="/tmp/subarg_$(date +%s)"
RESULTS_DIR="./subarg_results"
declare -a ALL_SUBDOMAINS=()
declare -a TOOLS=("subfinder" "sublist3r" "assetfinder" "amass" "dnsx" "dnsenum" "ffuf" "httpx" "httprobe" "anew")

# Function to display banner
show_banner() {
    clear
    echo -e "${CYAN}${BOLD}${ITALIC}"
    echo "  ███████╗██╗   ██╗██████╗  █████╗ ██████╗  ██████╗ "
    echo "  ██╔════╝██║   ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝ "
    echo "  ███████╗██║   ██║██████╔╝███████║██████╔╝██║  ███╗"
    echo "  ╚════██║██║   ██║██╔══██╗██╔══██║██╔══██╗██║   ██║"
    echo "  ███████║╚██████╔╝██████╔╝██║  ██║██║  ██║╚██████╔╝"
    echo "  ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ "
    echo -e "${NC}"
    echo -e "${YELLOW}${ITALIC}Author - Argha Dey (Mr. Ghost)${NC}\n"
}

# Function to display help menu
show_help() {
    show_banner
    echo -e "${GREEN}Usage: ./SubARG [OPTIONS]${NC}\n"
    echo -e "${YELLOW}Options:${NC}"
    echo -e "  ${BOLD}-d DOMAIN${NC}        Target domain (e.g., example.com)"
    echo -e "  ${BOLD}-dL FILE${NC}         File containing list of domains"
    echo -e "  ${BOLD}-o FILE${NC}          Output file name"
    echo -e "  ${BOLD}-oH FILE${NC}         Output in HTML format with specified filename"
    echo -e "  ${BOLD}-oX FILE${NC}         Output in XML format with specified filename"
    echo -e "  ${BOLD}-oC FILE${NC}         Output in CSV format with specified filename"
    echo -e "  ${BOLD}-oJ FILE${NC}         Output in JSON format with specified filename"
    echo -e "  ${BOLD}-h${NC}               Show this help menu"
    echo -e "\n${YELLOW}Examples:${NC}"
    echo -e "  ./SubARG -d example.com"
    echo -e "  ./SubARG -d example.com -o results.txt"
    echo -e "  ./SubARG -dL domains.txt -oJ results.json"
    echo -e "  ./SubARG -d example.com -oH report.html"
    echo -e "  ./SubARG -d example.com -oX data.xml"
    echo -e "  ./SubARG -d example.com -oC export.csv"
    echo -e "\n${MAGENTA}Note:${NC} Run as root or with sudo for automatic tool installation"
    exit 0
}

# Function to print tool execution message
print_tool_start() {
    echo -e "\n${MAGENTA}${BOLD}[*]${NC} ${CYAN}Running:${NC} ${GREEN}${ITALIC}$1${NC} ${CYAN}...${NC}"
}

# Function to filter DNS records
filter_dns_records() {
    local input_file=$1
    local target=$2
    local output_file=$3
    
    # Create temporary file
    local temp_file=$(mktemp)
    
    # Check if input file exists and has content
    if [ ! -s "$input_file" ]; then
        touch "$output_file"
        return
    fi
    
    # Patterns to exclude
    while IFS= read -r line || [ -n "$line" ]; do
        # Skip if line doesn't contain target domain
        if [[ ! "$line" =~ $target$ ]]; then
            continue
        fi
        
        # Skip if it's exactly the target domain
        if [[ "$line" == "$target" ]]; then
            continue
        fi
        
        # Skip DNS record patterns
        if [[ "$line" =~ ^ns-[0-9]+\..*$ ]] || \
           [[ "$line" =~ ^mx[0-9]*\..*$ ]] || \
           [[ "$line" =~ ^mail\..*$ ]] || \
           [[ "$line" =~ ^smtp\..*$ ]] || \
           [[ "$line" =~ ^relay\..*$ ]] || \
           [[ "$line" =~ \.awsdns- ]] || \
           [[ "$line" =~ \.cloudflare\. ]] || \
           [[ "$line" =~ \.akamai\. ]] || \
           [[ "$line" =~ \.cloudfront\. ]] || \
           [[ "$line" =~ \.googleusercontent\. ]] || \
           [[ "$line" =~ \.googlehosted\. ]] || \
           [[ "$line" =~ ^autodiscover\..*$ ]]; then
            continue
        fi
        
        # Skip if starts with ns, mx, mail, smtp, relay
        local first_part=$(echo "$line" | cut -d'.' -f1)
        if [[ "$first_part" =~ ^ns[0-9]*$ ]] || \
           [[ "$first_part" =~ ^mx[0-9]*$ ]] || \
           [[ "$first_part" == "mail" ]] || \
           [[ "$first_part" == "smtp" ]] || \
           [[ "$first_part" == "relay" ]] || \
           [[ "$first_part" == "pop" ]] || \
           [[ "$first_part" == "imap" ]]; then
            continue
        fi
        
        # Skip common DNS provider domains
        if [[ "$line" =~ \.awsdns\.org$ ]] || \
           [[ "$line" =~ \.awsdns\.co\.uk$ ]] || \
           [[ "$line" =~ \.awsdns\.com$ ]] || \
           [[ "$line" =~ \.awsdns\.net$ ]] || \
           [[ "$line" =~ \.cloudflare\.com$ ]] || \
           [[ "$line" =~ \.akamai\.net$ ]] || \
           [[ "$line" =~ \.akamaiedge\.net$ ]]; then
            continue
        fi
        
        # Write to output
        echo "$line" >> "$temp_file"
    done < "$input_file"
    
    # Sort and deduplicate
    if [ -s "$temp_file" ]; then
        sort -u "$temp_file" > "$output_file"
    else
        touch "$output_file"
    fi
    
    rm -f "$temp_file"
}

# Function to check and install tools
install_tools() {
    echo -e "\n${YELLOW}[!] Checking and installing required tools...${NC}"
    
    # Update package list
    sudo apt-get update > /dev/null 2>&1
    
    # Install Go if not present
    if ! command -v go &> /dev/null; then
        echo -e "${BLUE}[+] Installing Go...${NC}"
        sudo apt-get install -y golang-go > /dev/null 2>&1
    fi
    
    # Install Python3 and pip if not present
    if ! command -v python3 &> /dev/null; then
        echo -e "${BLUE}[+] Installing Python3...${NC}"
        sudo apt-get install -y python3 python3-pip > /dev/null 2>&1
    fi
    
    # Create tools directory
    mkdir -p $TOOLS_DIR
    mkdir -p $WORDLIST_DIR
    
    # Install subfinder
    if ! command -v subfinder &> /dev/null; then
        echo -e "${BLUE}[+] Installing Subfinder...${NC}"
        go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
        sudo cp $HOME/go/bin/subfinder /usr/local/bin/
    fi
    
    # Install assetfinder
    if ! command -v assetfinder &> /dev/null; then
        echo -e "${BLUE}[+] Installing Assetfinder...${NC}"
        go install -v github.com/tomnomnom/assetfinder@latest
        sudo cp $HOME/go/bin/assetfinder /usr/local/bin/
    fi
    
    # Install dnsx
    if ! command -v dnsx &> /dev/null; then
        echo -e "${BLUE}[+] Installing DNSx...${NC}"
        go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
        sudo cp $HOME/go/bin/dnsx /usr/local/bin/
    fi
    
    # Install httpx
    if ! command -v httpx &> /dev/null; then
        echo -e "${BLUE}[+] Installing HTTPx...${NC}"
        go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
        sudo cp $HOME/go/bin/httpx /usr/local/bin/
    fi
    
    # Install httprobe
    if ! command -v httprobe &> /dev/null; then
        echo -e "${BLUE}[+] Installing HTTPROBE...${NC}"
        go install -v github.com/tomnomnom/httprobe@latest
        sudo cp $HOME/go/bin/httprobe /usr/local/bin/
    fi
    
    # Install anew
    if ! command -v anew &> /dev/null; then
        echo -e "${BLUE}[+] Installing Anew...${NC}"
        go install -v github.com/tomnomnom/anew@latest
        sudo cp $HOME/go/bin/anew /usr/local/bin/
    fi
    
    # Install Sublist3r
    if ! command -v sublist3r &> /dev/null; then
        echo -e "${BLUE}[+] Installing Sublist3r...${NC}"
        cd $TOOLS_DIR
        git clone https://github.com/aboul3la/Sublist3r.git > /dev/null 2>&1
        cd Sublist3r
        pip3 install -r requirements.txt > /dev/null 2>&1
        sudo ln -sf $TOOLS_DIR/Sublist3r/sublist3r.py /usr/local/bin/sublist3r
        cd ..
    fi
    
    # Install dnsenum
    if ! command -v dnsenum &> /dev/null; then
        echo -e "${BLUE}[+] Installing DNSenum...${NC}"
        sudo apt-get install -y dnsenum > /dev/null 2>&1
    fi
    
    # Install amass
    if ! command -v amass &> /dev/null; then
        echo -e "${BLUE}[+] Installing Amass...${NC}"
        sudo apt-get install -y amass > /dev/null 2>&1
    fi
    
    # Install ffuf
    if ! command -v ffuf &> /dev/null; then
        echo -e "${BLUE}[+] Installing FFuf...${NC}"
        go install -v github.com/ffuf/ffuf@latest
        sudo cp $HOME/go/bin/ffuf /usr/local/bin/
    fi
    
    # Download wordlist if not present
    if [ ! -f "$WORDLIST" ]; then
        echo -e "${BLUE}[+] Downloading wordlists...${NC}"
        wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt -O $WORDLIST
    fi
    
    echo -e "${GREEN}[✓] All tools are installed and ready!${NC}\n"
}

# Function to run subfinder
run_subfinder() {
    print_tool_start "Subfinder - Passive subdomain enumeration"
    subfinder -d $DOMAIN -silent | anew $TEMP_DIR/subfinder_raw.txt
    
    # Filter DNS records
    filter_dns_records $TEMP_DIR/subfinder_raw.txt $DOMAIN $TEMP_DIR/subfinder_filtered.txt
    
    [ -s $TEMP_DIR/subfinder_filtered.txt ] && cat $TEMP_DIR/subfinder_filtered.txt >> $TEMP_DIR/all_subs.txt
    [ -s $TEMP_DIR/subfinder_filtered.txt ] && cat $TEMP_DIR/subfinder_filtered.txt > $TEMP_DIR/subfinder.txt
}

# Function to run sublist3r
run_sublist3r() {
    print_tool_start "Sublist3r - OSINT based subdomain enumeration"
    sublist3r -d $DOMAIN -o $TEMP_DIR/sublist3r_raw.txt > /dev/null 2>&1
    
    # Filter DNS records
    filter_dns_records $TEMP_DIR/sublist3r_raw.txt $DOMAIN $TEMP_DIR/sublist3r_filtered.txt
    
    [ -s $TEMP_DIR/sublist3r_filtered.txt ] && cat $TEMP_DIR/sublist3r_filtered.txt | anew $TEMP_DIR/all_subs.txt
    [ -s $TEMP_DIR/sublist3r_filtered.txt ] && cat $TEMP_DIR/sublist3r_filtered.txt > $TEMP_DIR/sublist3r.txt
}

# Function to run assetfinder
run_assetfinder() {
    print_tool_start "Assetfinder - Find domains and subdomains"
    assetfinder --subs-only $DOMAIN | anew $TEMP_DIR/assetfinder_raw.txt
    
    # Filter DNS records
    filter_dns_records $TEMP_DIR/assetfinder_raw.txt $DOMAIN $TEMP_DIR/assetfinder_filtered.txt
    
    [ -s $TEMP_DIR/assetfinder_filtered.txt ] && cat $TEMP_DIR/assetfinder_filtered.txt >> $TEMP_DIR/all_subs.txt
    [ -s $TEMP_DIR/assetfinder_filtered.txt ] && cat $TEMP_DIR/assetfinder_filtered.txt > $TEMP_DIR/assetfinder.txt
}

# Function to run amass
run_amass() {
    print_tool_start "Amass - In-depth attack surface mapping"
    amass enum -passive -d $DOMAIN -o $TEMP_DIR/amass_raw.txt > /dev/null 2>&1
    
    # Filter DNS records from amass output
    filter_dns_records $TEMP_DIR/amass_raw.txt $DOMAIN $TEMP_DIR/amass_filtered.txt
    
    [ -s $TEMP_DIR/amass_filtered.txt ] && cat $TEMP_DIR/amass_filtered.txt | anew $TEMP_DIR/all_subs.txt
    [ -s $TEMP_DIR/amass_filtered.txt ] && cat $TEMP_DIR/amass_filtered.txt > $TEMP_DIR/amass.txt
}

# Function to query crt.sh
run_crtsh() {
    print_tool_start "crt.sh - Certificate transparency logs"
    curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u | anew $TEMP_DIR/crtsh_raw.txt
    
    # Filter DNS records
    filter_dns_records $TEMP_DIR/crtsh_raw.txt $DOMAIN $TEMP_DIR/crtsh_filtered.txt
    
    [ -s $TEMP_DIR/crtsh_filtered.txt ] && cat $TEMP_DIR/crtsh_filtered.txt >> $TEMP_DIR/all_subs.txt
    [ -s $TEMP_DIR/crtsh_filtered.txt ] && cat $TEMP_DIR/crtsh_filtered.txt > $TEMP_DIR/crtsh.txt
}

# Function to run dnsenum
run_dnsenum() {
    print_tool_start "DNSenum - DNS information gathering"
    dnsenum --noreverse $DOMAIN --output $TEMP_DIR/dnsenum.xml > /dev/null 2>&1
    [ -f $TEMP_DIR/dnsenum.xml ] && grep -oP '(?<=name>)[^<]+' $TEMP_DIR/dnsenum.xml | grep $DOMAIN | anew $TEMP_DIR/dnsenum_raw.txt
    
    # Filter DNS records
    filter_dns_records $TEMP_DIR/dnsenum_raw.txt $DOMAIN $TEMP_DIR/dnsenum_filtered.txt
    
    [ -s $TEMP_DIR/dnsenum_filtered.txt ] && cat $TEMP_DIR/dnsenum_filtered.txt >> $TEMP_DIR/all_subs.txt
    [ -s $TEMP_DIR/dnsenum_filtered.txt ] && cat $TEMP_DIR/dnsenum_filtered.txt > $TEMP_DIR/dnsenum.txt
}

# Function to run DNSx for resolution
run_dnsx() {
    print_tool_start "DNSx - DNS toolkit for fast resolution"
    if [ -s $TEMP_DIR/all_subs.txt ]; then
        cat $TEMP_DIR/all_subs.txt | dnsx -silent -a -resp | anew $TEMP_DIR/resolved_subs.txt
    fi
}

# Function to run ffuf for bruteforcing
run_ffuf() {
    print_tool_start "FFuf - Fast web fuzzer for subdomain discovery"
    ffuf -w $WORDLIST -u "http://FUZZ.$DOMAIN" -H "User-Agent: Mozilla/5.0" -mc 200,301,302,403 -t 50 -o $TEMP_DIR/ffuf.json -of json -silent > /dev/null 2>&1
    [ -f $TEMP_DIR/ffuf.json ] && cat $TEMP_DIR/ffuf.json | jq -r '.results[].url' | cut -d'/' -f3 | anew $TEMP_DIR/ffuf_raw.txt
    
    # Filter DNS records
    filter_dns_records $TEMP_DIR/ffuf_raw.txt $DOMAIN $TEMP_DIR/ffuf_filtered.txt
    
    [ -s $TEMP_DIR/ffuf_filtered.txt ] && cat $TEMP_DIR/ffuf_filtered.txt >> $TEMP_DIR/all_subs.txt
    [ -s $TEMP_DIR/ffuf_filtered.txt ] && cat $TEMP_DIR/ffuf_filtered.txt > $TEMP_DIR/ffuf.txt
}

# Function to run httprobe for live subdomain detection
run_httprobe() {
    print_tool_start "HTTPROBE - Tool for probing HTTP/HTTPS"
    if [ -s $TEMP_DIR/resolved_subs.txt ]; then
        cat $TEMP_DIR/resolved_subs.txt | httprobe -c 50 -t 3000 | anew $TEMP_DIR/httprobe_subs.txt
        [ -s $TEMP_DIR/httprobe_subs.txt ] && cat $TEMP_DIR/httprobe_subs.txt >> $TEMP_DIR/live_subs.txt
    fi
}

# Function to check live subdomains with HTTPx
run_httpx() {
    print_tool_start "HTTPx - HTTP toolkit for live subdomain verification"
    if [ -s $TEMP_DIR/resolved_subs.txt ]; then
        cat $TEMP_DIR/resolved_subs.txt | httpx -silent -title -status-code -tech-detect -o $TEMP_DIR/httpx_subs.txt
        
        # If httpx fails or returns no results, try httprobe
        if [ ! -s $TEMP_DIR/httpx_subs.txt ]; then
            echo -e "${YELLOW}[!] HTTPx returned no results, trying HTTPROBE...${NC}"
            run_httprobe
        else
            cat $TEMP_DIR/httpx_subs.txt >> $TEMP_DIR/live_subs.txt
        fi
    else
        # If no resolved subdomains, try httprobe directly on all subdomains
        if [ -s $TEMP_DIR/all_subs.txt ]; then
            echo -e "${YELLOW}[!] No resolved subdomains, trying HTTPROBE on all subdomains...${NC}"
            cat $TEMP_DIR/all_subs.txt | httprobe -c 50 -t 3000 | anew $TEMP_DIR/live_subs.txt
        fi
    fi
}

# Function to process domain list
process_domain_list() {
    if [ ! -f "$DOMAIN_LIST" ]; then
        echo -e "${RED}[!] Domain list file not found: $DOMAIN_LIST${NC}"
        exit 1
    fi
    
    while IFS= read -r target_domain || [ -n "$target_domain" ]; do
        if [ -n "$target_domain" ]; then
            echo -e "\n${GREEN}[+] Processing domain: $target_domain${NC}"
            DOMAIN="$target_domain"
            TEMP_DIR="/tmp/subarg_$(date +%s)_${target_domain//./_}"
            mkdir -p $TEMP_DIR
            run_all_tools
            save_results
        fi
    done < "$DOMAIN_LIST"
}

# Function to run all tools
run_all_tools() {
    echo -e "\n${BLUE}${BOLD}[+] Starting subdomain enumeration for:${NC} ${GREEN}$DOMAIN${NC}"
    
    # Create temporary directory
    rm -rf $TEMP_DIR
    mkdir -p $TEMP_DIR
    
    # Run all enumeration tools
    run_subfinder
    run_sublist3r
    run_assetfinder
    run_amass
    run_crtsh
    run_dnsenum
    run_ffuf
    run_dnsx
    
    # Run HTTP check - httpx with httprobe fallback
    run_httpx
    
    # Final filtering of DNS records
    print_tool_start "Filtering DNS records"
    filter_dns_records $TEMP_DIR/all_subs.txt $DOMAIN $TEMP_DIR/all_subs_filtered.txt
    mv $TEMP_DIR/all_subs_filtered.txt $TEMP_DIR/all_subs.txt
    
    # Sort and get unique subdomains
    sort -u $TEMP_DIR/all_subs.txt 2>/dev/null > $TEMP_DIR/unique_subs.txt
}

# Function to save results in different formats
save_results() {
    mkdir -p $RESULTS_DIR
    
    # If no specific output file is set, use default naming
    if [ -z "$OUTPUT_FILE" ]; then
        OUTPUT_FILE="$RESULTS_DIR/subdomains_${DOMAIN}_$(date +%Y%m%d_%H%M%S)"
    fi
    
    # Save in text format by default (unless other format specified)
    if [ -s $TEMP_DIR/unique_subs.txt ] && [ "$OUTPUT_FORMAT" = "txt" ]; then
        if [[ "$OUTPUT_FILE" != *.* ]]; then
            OUTPUT_FILE="$OUTPUT_FILE.txt"
        fi
        cp $TEMP_DIR/unique_subs.txt "$OUTPUT_FILE"
        echo -e "${GREEN}[✓] Text results saved to: ${OUTPUT_FILE}${NC}"
        echo -e "${YELLOW}[i] Found $(wc -l < $TEMP_DIR/unique_subs.txt) unique subdomains${NC}"
    fi
    
    # Save in requested format
    case $OUTPUT_FORMAT in
        "html")
            # Ensure proper file extension
            if [[ "$OUTPUT_FILE" != *.html ]] && [[ "$OUTPUT_FILE" != *.htm ]]; then
                OUTPUT_FILE="$OUTPUT_FILE.html"
            fi
            echo "<html><head><title>SubARG Results for $DOMAIN</title></head><body>" > "$OUTPUT_FILE"
            echo "<h1>Subdomain Enumeration Results</h1>" >> "$OUTPUT_FILE"
            echo "<h3>Domain: $DOMAIN</h3>" >> "$OUTPUT_FILE"
            echo "<h3>Date: $(date)</h3>" >> "$OUTPUT_FILE"
            echo "<h3>Total Unique Subdomains: $(wc -l < $TEMP_DIR/unique_subs.txt 2>/dev/null || echo 0)</h3>" >> "$OUTPUT_FILE"
            echo "<h4>Subdomains:</h4><ul>" >> "$OUTPUT_FILE"
            [ -s $TEMP_DIR/unique_subs.txt ] && while read sub; do echo "<li>$sub</li>" >> "$OUTPUT_FILE"; done < $TEMP_DIR/unique_subs.txt
            echo "</ul></body></html>" >> "$OUTPUT_FILE"
            echo -e "${GREEN}[✓] HTML results saved to: ${OUTPUT_FILE}${NC}"
            ;;
        "xml")
            # Ensure proper file extension
            if [[ "$OUTPUT_FILE" != *.xml ]]; then
                OUTPUT_FILE="$OUTPUT_FILE.xml"
            fi
            echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" > "$OUTPUT_FILE"
            echo "<subdomain_scan>" >> "$OUTPUT_FILE"
            echo "  <domain>$DOMAIN</domain>" >> "$OUTPUT_FILE"
            echo "  <date>$(date)</date>" >> "$OUTPUT_FILE"
            echo "  <subdomains>" >> "$OUTPUT_FILE"
            [ -s $TEMP_DIR/unique_subs.txt ] && while read sub; do echo "    <subdomain>$sub</subdomain>" >> "$OUTPUT_FILE"; done < $TEMP_DIR/unique_subs.txt
            echo "  </subdomains>" >> "$OUTPUT_FILE"
            echo "</subdomain_scan>" >> "$OUTPUT_FILE"
            echo -e "${GREEN}[✓] XML results saved to: ${OUTPUT_FILE}${NC}"
            ;;
        "csv")
            # Ensure proper file extension
            if [[ "$OUTPUT_FILE" != *.csv ]]; then
                OUTPUT_FILE="$OUTPUT_FILE.csv"
            fi
            echo "Domain,Subdomain,Discovery_Date" > "$OUTPUT_FILE"
            [ -s $TEMP_DIR/unique_subs.txt ] && while read sub; do echo "$DOMAIN,$sub,$(date +%Y-%m-%d)" >> "$OUTPUT_FILE"; done < $TEMP_DIR/unique_subs.txt
            echo -e "${GREEN}[✓] CSV results saved to: ${OUTPUT_FILE}${NC}"
            ;;
        "json")
            # Ensure proper file extension
            if [[ "$OUTPUT_FILE" != *.json ]]; then
                OUTPUT_FILE="$OUTPUT_FILE.json"
            fi
            echo "{\"domain\":\"$DOMAIN\",\"date\":\"$(date)\",\"subdomains\":[" > "$OUTPUT_FILE"
            if [ -s $TEMP_DIR/unique_subs.txt ]; then
                subs=$(cat $TEMP_DIR/unique_subs.txt | sed 's/.*/"&"/' | tr '\n' ',')
                echo "${subs%,}]}" >> "$OUTPUT_FILE"
            else
                echo "]}" >> "$OUTPUT_FILE"
            fi
            echo -e "${GREEN}[✓] JSON results saved to: ${OUTPUT_FILE}${NC}"
            ;;
    esac
    
    # Show live subdomains if any
    if [ -s $TEMP_DIR/live_subs.txt ]; then
        echo -e "\n${GREEN}[+] Live Subdomains:${NC}"
        cat $TEMP_DIR/live_subs.txt
        cp $TEMP_DIR/live_subs.txt "$RESULTS_DIR/live_${DOMAIN}.txt"
    fi
}

# Main function
main() {
    # Check if no arguments provided
    if [ $# -eq 0 ]; then
        show_help
    fi
    
    # Variables for output parsing
    local output_arg=""
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d)
                DOMAIN="$2"
                shift 2
                ;;
            -dL)
                DOMAIN_LIST="$2"
                shift 2
                ;;
            -o)
                OUTPUT_FILE="$2"
                shift 2
                ;;
            -oH)
                OUTPUT_FORMAT="html"
                if [[ -n "$2" && ! "$2" =~ ^- ]]; then
                    OUTPUT_FILE="$2"
                    shift
                fi
                shift
                ;;
            -oX)
                OUTPUT_FORMAT="xml"
                if [[ -n "$2" && ! "$2" =~ ^- ]]; then
                    OUTPUT_FILE="$2"
                    shift
                fi
                shift
                ;;
            -oC)
                OUTPUT_FORMAT="csv"
                if [[ -n "$2" && ! "$2" =~ ^- ]]; then
                    OUTPUT_FILE="$2"
                    shift
                fi
                shift
                ;;
            -oJ)
                OUTPUT_FORMAT="json"
                if [[ -n "$2" && ! "$2" =~ ^- ]]; then
                    OUTPUT_FILE="$2"
                    shift
                fi
                shift
                ;;
            -h)
                show_help
                ;;
            *)
                echo -e "${RED}[!] Unknown option: $1${NC}"
                show_help
                ;;
        esac
    done
    
    # Show banner
    show_banner
    
    # Check if domain or domain list is provided
    if [ -z "$DOMAIN" ] && [ -z "$DOMAIN_LIST" ]; then
        echo -e "${RED}[!] Please provide a domain (-d) or domain list (-dL)${NC}"
        show_help
    fi
    
    # Install tools if needed
    install_tools
    
    # Process single domain or domain list
    if [ -n "$DOMAIN_LIST" ]; then
        process_domain_list
    else
        run_all_tools
        save_results
    fi
    
    # Cleanup
    rm -rf $TEMP_DIR
    
    echo -e "\n${GREEN}[✓] Subdomain enumeration completed!${NC}"
    echo -e "${YELLOW}[i] Results saved in: $RESULTS_DIR/${NC}"
}

# Run main function with all arguments
main "$@"
