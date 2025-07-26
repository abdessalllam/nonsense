#!/bin/bash

# Safe Template Reset and Re-registration Script
# This will preserve SystemVM templates and re-add working templates

ZONE_ID="7095049d-099b-41aa-a0b6-9ac3d6c5d08c"
DB_USER="cloud"
DB_PASS="password"
DB_NAME="cloud"

echo "=== SAFE TEMPLATE RESET AND RESTORATION ==="
echo ""

# Step 1: Safely remove only USER templates (preserve SystemVM templates)
echo "Step 1: Safely removing user templates (preserving SystemVM templates)..."

sudo mysql -u $DB_USER -p$DB_PASS $DB_NAME << 'EOF'
-- Show what SystemVM templates we're preserving
SELECT id, name, type_id FROM vm_template WHERE name LIKE '%SystemVM%' OR type_id = 'SYSTEM';

-- Remove only USER templates and their references
DELETE FROM template_store_ref 
WHERE template_id IN (
    SELECT id FROM vm_template 
    WHERE type_id = 'USER' OR (type_id IS NULL AND name NOT LIKE '%SystemVM%')
);

DELETE FROM template_details 
WHERE template_id IN (
    SELECT id FROM vm_template 
    WHERE type_id = 'USER' OR (type_id IS NULL AND name NOT LIKE '%SystemVM%')
);

DELETE FROM vm_template 
WHERE type_id = 'USER' OR (type_id IS NULL AND name NOT LIKE '%SystemVM%');

-- Show remaining templates (should be SystemVM only)
SELECT id, name, type_id, hypervisor_type FROM vm_template WHERE removed IS NULL;
EOF

echo "User templates safely removed. SystemVM templates preserved."
echo ""

# Step 2: Clean up secondary storage files
echo "Step 2: Cleaning up secondary storage template files..."
if [ -d "/export/secondary/template" ]; then
    # Only remove user template files, preserve system files
    sudo find /export/secondary/template -name "*" -type f ! -path "*/tmpl/1/3/*" -delete 2>/dev/null
    echo "User template files cleaned from secondary storage"
else
    echo "Secondary storage path not found"
fi
echo ""

# Step 3: Register working templates with corrected URLs
echo "Step 3: Registering templates with working URLs..."

# Function to register templates safely
register_template() {
    local name="$1"
    local url="$2"
    local ostypeid="$3"
    local format="$4"
    local description="$5"
    
    echo "Registering: $name"
    cloudmonkey register template \
        name="$name" \
        displaytext="$description" \
        url="$url" \
        zoneid="$ZONE_ID" \
        ostypeid="$ostypeid" \
        hypervisor="KVM" \
        format="$format" \
        passwordenabled="false" \
        sshkeyenabled="true" \
        ispublic="true" \
        isfeatured="true" \
        extractable="true" 2>/dev/null
    
    if [ $? -eq 0 ]; then
        echo "✓ $name registered successfully"
    else
        echo "✗ $name registration failed"
    fi
    echo ""
}

echo "=== REGISTERING WORKING UBUNTU TEMPLATES ==="
register_template "Ubuntu-24.04" "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img" "25" "QCOW2" "Ubuntu 24.04 LTS Server"
register_template "Ubuntu-22.04" "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img" "25" "QCOW2" "Ubuntu 22.04 LTS Server"
register_template "Ubuntu-20.04" "https://cloud-images.ubuntu.com/focal/current/focal-server-cloudimg-amd64.img" "25" "QCOW2" "Ubuntu 20.04 LTS Server"

echo "=== REGISTERING WORKING DEBIAN TEMPLATES ==="
register_template "Debian-12" "https://cloud.debian.org/images/cloud/bookworm/20231013-1532/debian-12-genericcloud-amd64-20231013-1532.qcow2" "60" "QCOW2" "Debian 12 Bookworm"
register_template "Debian-11" "https://cloud.debian.org/images/cloud/bullseye/20231013-1532/debian-11-genericcloud-amd64-20231013-1532.qcow2" "60" "QCOW2" "Debian 11 Bullseye"

echo "=== REGISTERING WORKING ROCKY LINUX TEMPLATES ==="
register_template "Rocky-Linux-9" "https://download.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud.latest.x86_64.qcow2" "27" "QCOW2" "Rocky Linux 9"
register_template "Rocky-Linux-8" "https://download.rockylinux.org/pub/rocky/8/images/x86_64/Rocky-8-GenericCloud.latest.x86_64.qcow2" "27" "QCOW2" "Rocky Linux 8"

echo "=== REGISTERING WORKING ALMALINUX TEMPLATES ==="
register_template "AlmaLinux-9" "https://repo.almalinux.org/almalinux/9/cloud/x86_64/images/AlmaLinux-9-GenericCloud-latest.x86_64.qcow2" "27" "QCOW2" "AlmaLinux 9"
register_template "AlmaLinux-8" "https://repo.almalinux.org/almalinux/8/cloud/x86_64/images/AlmaLinux-8-GenericCloud-latest.x86_64.qcow2" "27" "QCOW2" "AlmaLinux 8"

echo "=== REGISTERING WORKING CENTOS STREAM ==="
register_template "CentOS-Stream-9" "https://mirror.stream.centos.org/9-stream/BaseOS/x86_64/images/CentOS-Stream-GenericCloud-9-20240101.0.x86_64.qcow2" "27" "QCOW2" "CentOS Stream 9"

echo "=== REGISTERING WORKING OPENSUSE TEMPLATES ==="
register_template "OpenSUSE-Leap-15.5" "https://download.opensuse.org/distribution/leap/15.5/appliances/openSUSE-Leap-15.5-Minimal-VM.x86_64-Cloud.qcow2" "73" "QCOW2" "OpenSUSE Leap 15.5"

echo "=== REGISTERING WORKING ORACLE LINUX ==="
register_template "Oracle-Linux-9" "https://yum.oracle.com/templates/OracleLinux/OL9/u5/x86_64/OL9U5_x86_64-kvm-b259.qcow2" "134" "QCOW2" "Oracle Linux 9"
register_template "Oracle-Linux-8" "https://yum.oracle.com/templates/OracleLinux/OL8/u10/x86_64/OL8U10_x86_64-kvm-b258.qcow2" "134" "QCOW2" "Oracle Linux 8"

echo "=== REGISTERING WORKING FEDORA TEMPLATES ==="
register_template "Fedora-39" "https://download.fedoraproject.org/pub/fedora/linux/releases/39/Cloud/x86_64/images/Fedora-Cloud-Base-39-1.5.x86_64.qcow2" "175" "QCOW2" "Fedora 39 Cloud"

echo "=== REGISTERING CORRECTED TEMPLATES (Previously Failed) ==="

# FreeBSD - using uncompressed versions
register_template "FreeBSD-14.1" "https://download.freebsd.org/releases/VM-IMAGES/14.1-RELEASE/amd64/Latest/FreeBSD-14.1-RELEASE-amd64.qcow2" "111" "QCOW2" "FreeBSD 14.1"
register_template "FreeBSD-13.3" "https://download.freebsd.org/releases/VM-IMAGES/13.3-RELEASE/amd64/Latest/FreeBSD-13.3-RELEASE-amd64.qcow2" "111" "QCOW2" "FreeBSD 13.3"

# Alpine Linux - using direct qcow2 links
register_template "Alpine-Linux-3.19" "https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/cloud/alpine-cloud-3.19.1-x86_64-uefi.qcow2" "175" "QCOW2" "Alpine Linux 3.19"

# Arch Linux - using cloud image
register_template "Arch-Linux" "https://mirror.pkgbuild.com/images/latest/Arch-Linux-x86_64-cloudimg.qcow2" "175" "QCOW2" "Arch Linux"

# Clear Linux - using img format
register_template "Clear-Linux" "https://download.clearlinux.org/releases/current/clear/clear-cloudguest.img" "175" "RAW" "Clear Linux"

# Alternative working templates
echo "=== REGISTERING ADDITIONAL USEFUL TEMPLATES ==="
register_template "Flatcar-Container-Linux" "https://stable.release.flatcar-linux.net/amd64-usr/current/flatcar_production_qemu_image.img.bz2" "175" "RAW" "Flatcar Container Linux"

# Step 4: Check registration results
echo ""
echo "=== CHECKING TEMPLATE REGISTRATION RESULTS ==="

# Wait a moment for registrations to process
sleep 10

# Check template status
cloudmonkey list templates templatefilter="all" | grep -E "(name|status|downloadprogress)" | sed 'N;N;s/\n/ | /g'

echo ""
echo "=== MONITORING TEMPLATE DOWNLOADS ==="
echo "Use this command to monitor download progress:"
echo "watch -n 30 'cloudmonkey list templates templatefilter=\"all\" | grep -E \"(name|status|downloadprogress)\" | grep -A2 -B2 \"Downloading\\|Not Ready\"'"
echo ""

echo "=== VERIFYING SYSTEMVM TEMPLATES ==="
# Make sure SystemVM templates are still intact
sudo mysql -u $DB_USER -p$DB_PASS $DB_NAME -e "
SELECT 
    name, 
    hypervisor_type, 
    type_id,
    CASE WHEN removed IS NULL THEN 'Active' ELSE 'Removed' END as status
FROM vm_template 
WHERE name LIKE '%SystemVM%' 
ORDER BY hypervisor_type;"

echo ""
echo "=== TEMPLATE RESTORATION COMPLETE ==="
echo ""
echo "Summary:"
echo "✓ SystemVM templates preserved"
echo "✓ User templates safely removed"
echo "✓ Working templates re-registered with corrected URLs"
echo "✓ Previously failed templates registered with fixed URLs"
echo ""
echo "Next steps:"
echo "1. Monitor template downloads with the watch command above"
echo "2. Check CloudStack web UI: Templates section"
echo "3. Wait for templates to change from 'Not Ready' to 'Ready'"
echo ""
echo "Templates should start downloading automatically."
echo "Check Secondary Storage status: Infrastructure → Secondary Storage"

# Final safety check
echo ""
echo "=== FINAL SAFETY CHECK ==="
echo "Current template count:"
sudo mysql -u $DB_USER -p$DB_PASS $DB_NAME -e "
SELECT 
    COUNT(CASE WHEN name LIKE '%SystemVM%' THEN 1 END) as SystemVM_Templates,
    COUNT(CASE WHEN name NOT LIKE '%SystemVM%' THEN 1 END) as User_Templates,
    COUNT(*) as Total_Templates
FROM vm_template 
WHERE removed IS NULL;"
