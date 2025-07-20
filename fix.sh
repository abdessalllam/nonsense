#!/bin/bash

# Network Diagnostic and Fix Script for Rocky Linux Bridge/VLAN Setup
# Usage: sudo ./network-fix.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root (use sudo)"
   exit 1
fi

log "Starting network diagnostic and repair..."

# Function to check interface status
check_interface_status() {
    local iface=$1
    local carrier_file="/sys/class/net/$iface/carrier"
    
    if [[ -f "$carrier_file" ]]; then
        local carrier=$(cat "$carrier_file" 2>/dev/null || echo "0")
        if [[ "$carrier" == "1" ]]; then
            echo "UP"
        else
            echo "DOWN"
        fi
    else
        echo "NOT_FOUND"
    fi
}

# Function to get interface IP
get_interface_ip() {
    local iface=$1
    ip addr show "$iface" 2>/dev/null | grep "inet " | awk '{print $2}' | head -1
}

# Function to detect gateway from IP range
detect_gateway() {
    local ip_with_mask=$1
    local ip=$(echo "$ip_with_mask" | cut -d'/' -f1)
    local mask=$(echo "$ip_with_mask" | cut -d'/' -f2)
    
    # Extract network portion and assume .225 is gateway for /28 networks
    local network=$(echo "$ip" | cut -d'.' -f1-3)
    echo "${network}.225"
}

log "=== PHASE 1: DIAGNOSTIC ==="

# Check physical interfaces
log "Checking physical interfaces..."
for iface in eno1 eno2 eno3 eno4; do
    status=$(check_interface_status "$iface")
    ip=$(get_interface_ip "$iface")
    log "  $iface: Status=$status, IP=${ip:-none}"
done

# Check VLAN interfaces
log "Checking VLAN interfaces..."
for vlan in eno1.100 eno1.200; do
    if ip link show "$vlan" &>/dev/null; then
        status=$(check_interface_status "$vlan")
        log "  $vlan: Status=$status"
    else
        warning "  $vlan: Not found"
    fi
done

# Check bridges
log "Checking bridges..."
cloudbr0_ip=$(get_interface_ip "cloudbr0")
cloudbr1_ip=$(get_interface_ip "cloudbr1")
cloudbr0_status=$(check_interface_status "cloudbr0")
cloudbr1_status=$(check_interface_status "cloudbr1")

log "  cloudbr0: Status=$cloudbr0_status, IP=${cloudbr0_ip:-none}"
log "  cloudbr1: Status=$cloudbr1_status, IP=${cloudbr1_ip:-none}"

# Check current routing
log "Checking routing table..."
default_route=$(ip route show default 2>/dev/null | head -1)
log "  Default route: ${default_route:-none}"

# Check DNS
log "Checking DNS configuration..."
if [[ -f /etc/resolv.conf ]]; then
    dns_servers=$(grep "nameserver" /etc/resolv.conf | awk '{print $2}' | tr '\n' ' ')
    log "  DNS servers: ${dns_servers:-none}"
fi

log "=== PHASE 2: PROBLEM DETECTION ==="

problems=()
fixes=()

# Check if eno1 is up (required for VLANs)
eno1_status=$(check_interface_status "eno1")
if [[ "$eno1_status" != "UP" ]]; then
    problems+=("eno1 interface is down")
    fixes+=("bring_up_eno1")
fi

# Check if we have bridge IPs
if [[ -z "$cloudbr0_ip" && -z "$cloudbr1_ip" ]]; then
    problems+=("No IP addresses on bridges")
    fixes+=("configure_bridge_ips")
elif [[ -z "$cloudbr0_ip" ]]; then
    problems+=("cloudbr0 has no IP address")
    fixes+=("fix_cloudbr0_ip")
elif [[ -z "$cloudbr1_ip" ]]; then
    problems+=("cloudbr1 has no IP address")
    fixes+=("fix_cloudbr1_ip")
fi

# Check default route
if [[ -z "$default_route" ]]; then
    problems+=("No default route configured")
    fixes+=("add_default_route")
fi

# Check DNS
if [[ -z "$dns_servers" ]]; then
    problems+=("No DNS servers configured")
    fixes+=("configure_dns")
fi

if [[ ${#problems[@]} -eq 0 ]]; then
    success "No obvious problems detected. Testing connectivity..."
else
    warning "Found ${#problems[@]} problem(s):"
    for problem in "${problems[@]}"; do
        warning "  - $problem"
    done
fi

log "=== PHASE 3: FIXES ==="

# Function implementations
bring_up_eno1() {
    log "Bringing up eno1 interface..."
    if nmcli connection show eno1 &>/dev/null; then
        nmcli connection up eno1
    else
        log "Creating eno1 connection..."
        nmcli connection add type ethernet con-name eno1 ifname eno1 \
            ipv4.method disabled ipv6.method link-local connection.autoconnect yes
        nmcli connection up eno1
    fi
    sleep 2
}

configure_bridge_ips() {
    log "Configuring bridge IP addresses..."
    # This would need specific IP configuration - using placeholders
    warning "Bridge IP configuration requires manual setup with your specific IPs"
}

fix_cloudbr0_ip() {
    log "Attempting to fix cloudbr0 IP configuration..."
    nmcli connection up cloudbr0 || warning "Failed to bring up cloudbr0"
}

fix_cloudbr1_ip() {
    log "Attempting to fix cloudbr1 IP configuration..."
    nmcli connection up cloudbr1 || warning "Failed to bring up cloudbr1"
}

add_default_route() {
    log "Adding default route..."
    # Determine which bridge should have the default route
    local main_ip=""
    local gateway=""
    
    if [[ -n "$cloudbr0_ip" ]]; then
        main_ip="$cloudbr0_ip"
        gateway=$(detect_gateway "$cloudbr0_ip")
        ip route add default via "$gateway" dev cloudbr0 2>/dev/null || warning "Failed to add default route via cloudbr0"
    elif [[ -n "$cloudbr1_ip" ]]; then
        main_ip="$cloudbr1_ip"
        gateway=$(detect_gateway "$cloudbr1_ip")
        ip route add default via "$gateway" dev cloudbr1 2>/dev/null || warning "Failed to add default route via cloudbr1"
    fi
    
    if [[ -n "$gateway" ]]; then
        log "Added default route via $gateway"
    fi
}

configure_dns() {
    log "Configuring DNS servers..."
    echo "nameserver 8.8.8.8" > /etc/resolv.conf
    echo "nameserver 8.8.4.4" >> /etc/resolv.conf
}

# Execute fixes
for fix in "${fixes[@]}"; do
    log "Executing fix: $fix"
    $fix
done

log "=== PHASE 4: CONNECTIVITY TEST ==="

# Test connectivity
test_connectivity() {
    local target=$1
    local description=$2
    
    log "Testing $description ($target)..."
    if ping -c 3 -W 2 "$target" &>/dev/null; then
        success "  ✓ $description reachable"
        return 0
    else
        error "  ✗ $description unreachable"
        return 1
    fi
}

# Find gateway to test
gateway=""
if [[ -n "$cloudbr0_ip" ]]; then
    gateway=$(detect_gateway "$cloudbr0_ip")
elif [[ -n "$cloudbr1_ip" ]]; then
    gateway=$(detect_gateway "$cloudbr1_ip")
fi

connectivity_ok=true

if [[ -n "$gateway" ]]; then
    test_connectivity "$gateway" "Gateway" || connectivity_ok=false
fi

test_connectivity "8.8.8.8" "Internet (Google DNS)" || connectivity_ok=false
test_connectivity "google.com" "DNS resolution" || connectivity_ok=false

log "=== FINAL STATUS ==="

if [[ "$connectivity_ok" == true ]]; then
    success "Network connectivity is working!"
else
    error "Network connectivity issues remain. Manual intervention may be required."
    
    log "=== MANUAL TROUBLESHOOTING SUGGESTIONS ==="
    warning "Try these manual steps:"
    warning "1. Check bridge configuration: brctl show"
    warning "2. Restart NetworkManager: systemctl restart NetworkManager"
    warning "3. Check specific interface routing: ip route get 8.8.8.8"
    warning "4. Verify VLAN configuration: ip link show | grep vlan"
    
    # Show current network state for debugging
    log "=== CURRENT NETWORK STATE ==="
    log "IP addresses:"
    ip addr show | grep -E "^[0-9]+:|inet " | sed 's/^/  /'
    
    log "Routing table:"
    ip route show | sed 's/^/  /'
    
    log "Bridge status:"
    brctl show 2>/dev/null | sed 's/^/  /' || warning "brctl not available"
fi

log "Network diagnostic and repair script completed."
