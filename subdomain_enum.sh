#!/bin/bash

# ==============================================================================
# Subdomain Enumeration Wrapper
# Chains Amass, Sublist3r, and Subfinder to discover subdomains, then deduplicates.
# ==============================================================================

# ANSI Color Codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}"
echo "  ___      _   ___                    "
echo " / __| _  | | | __| _ _  _  _  _ __   "
echo " \__ \| || | | |__ | ' \| || || '  \  "
echo " |___/ \_,_| |____||_||_|\_,_||_|_|_| "
echo "                                      "
echo -e " Automated OSINT Subdomain Enumeration ${NC}"
echo "=================================================="

# Check for target argument
if [ -z "$1" ]; then
    echo -e "${RED}[-] Usage: $0 <domain.com>${NC}"
    exit 1
fi

DOMAIN=$1
OUT_DIR="${DOMAIN}_recon_$(date +%Y%m%d_%H%M%S)"

# Function to check if a command exists
check_tool() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}[-] Error: $1 is not installed or not in PATH.${NC}"
        echo -e "[*] Please install $1 to use this wrapper."
        exit 1
    fi
}

# Verify required tools are installed
echo -e "${YELLOW}[*] Checking dependencies...${NC}"
check_tool "amass"
check_tool "sublist3r"
check_tool "subfinder" # Added Subfinder as it is an industry standard

# Create output directory
mkdir -p "$OUT_DIR"
echo -e "${GREEN}[+] Created output directory: ${OUT_DIR}${NC}\n"

# ------------------------------------------------------------------------------
# 1. Subfinder
# ------------------------------------------------------------------------------
echo -e "${YELLOW}[*] Starting Subfinder...${NC}"
subfinder -d "$DOMAIN" -all -silent > "$OUT_DIR/subfinder.txt"
echo -e "${GREEN}[+] Subfinder complete. Found $(wc -l < "$OUT_DIR/subfinder.txt") subdomains.${NC}\n"

# ------------------------------------------------------------------------------
# 2. Sublist3r
# ------------------------------------------------------------------------------
echo -e "${YELLOW}[*] Starting Sublist3r...${NC}"
# Running silently and redirecting stderr to /dev/null to keep terminal clean
sublist3r -d "$DOMAIN" -o "$OUT_DIR/sublist3r.txt" > /dev/null 2>&1
if [ -f "$OUT_DIR/sublist3r.txt" ]; then
    echo -e "${GREEN}[+] Sublist3r complete. Found $(wc -l < "$OUT_DIR/sublist3r.txt") subdomains.${NC}\n"
else
    echo -e "${RED}[-] Sublist3r failed to write output. Creating empty file.${NC}\n"
    touch "$OUT_DIR/sublist3r.txt"
fi

# ------------------------------------------------------------------------------
# 3. Amass (Passive Mode)
# ------------------------------------------------------------------------------
echo -e "${YELLOW}[*] Starting Amass (Passive Mode)...${NC}"
echo -e "${YELLOW}[!] This may take a few minutes depending on the target size.${NC}"
amass enum -passive -d "$DOMAIN" -nolocaldb > "$OUT_DIR/amass.txt" 2>/dev/null
echo -e "${GREEN}[+] Amass complete. Found $(wc -l < "$OUT_DIR/amass.txt") subdomains.${NC}\n"

# ------------------------------------------------------------------------------
# Data Aggregation and Deduplication
# ------------------------------------------------------------------------------
echo -e "${YELLOW}[*] Merging and deduplicating results...${NC}"
cat "$OUT_DIR"/subfinder.txt "$OUT_DIR"/sublist3r.txt "$OUT_DIR"/amass.txt | tr '[:upper:]' '[:lower:]' | sed 's/^\*\.//' | sort -u > "$OUT_DIR/final_subdomains.txt"

FINAL_COUNT=$(wc -l < "$OUT_DIR/final_subdomains.txt")

echo "=================================================="
echo -e "${GREEN}[+] Enumeration Finished!${NC}"
echo -e "${GREEN}[+] Total unique subdomains discovered: ${FINAL_COUNT}${NC}"
echo -e "${GREEN}[+] Results saved to: ${OUT_DIR}/final_subdomains.txt${NC}"
echo "=================================================="