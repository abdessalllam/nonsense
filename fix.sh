#!/bin/bash

# CloudStack Template Registration Script
# Make sure you have cloudmonkey configured and your zone ID ready

# Set your zone ID (replace with your actual zone ID)
ZONE_ID="MUSTBEFILLEDXD"

# Function to register templates
register_template() {
    local name="$1"
    local url="$2"
    local ostypeid="$3"
    local format="$4"
    
    echo "Registering template: $name"
    cloudmonkey register template \
        name="$name" \
        displaytext="$name" \
        url="$url" \
        zoneid="$ZONE_ID" \
        ostypeid="$ostypeid" \
        hypervisor="KVM" \
        format="$format" \
        passwordenabled="false" \
        sshkeyenabled="true" \
        ispublic="true" \
        isfeatured="true" \
        extractable="true"
    
    echo "Template $name registration initiated"
    echo "----------------------------------------"
}

# Ubuntu Templates
echo "=== UBUNTU TEMPLATES ==="
register_template "Ubuntu-24.04" "https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img" "25" "QCOW2"
register_template "Ubuntu-22.04" "https://cloud-images.ubuntu.com/releases/22.04/release/ubuntu-22.04-server-cloudimg-amd64.img" "25" "QCOW2"
register_template "Ubuntu-20.04" "https://cloud-images.ubuntu.com/releases/20.04/release/ubuntu-20.04-server-cloudimg-amd64.img" "25" "QCOW2"

# Debian Templates
echo "=== DEBIAN TEMPLATES ==="
register_template "Debian-12" "https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2" "60" "QCOW2"
register_template "Debian-11" "https://cloud.debian.org/images/cloud/bullseye/latest/debian-11-genericcloud-amd64.qcow2" "60" "QCOW2"

# Rocky Linux Templates
echo "=== ROCKY LINUX TEMPLATES ==="
register_template "Rocky-Linux-9" "https://download.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud.latest.x86_64.qcow2" "27" "QCOW2"
register_template "Rocky-Linux-8" "https://download.rockylinux.org/pub/rocky/8/images/x86_64/Rocky-8-GenericCloud.latest.x86_64.qcow2" "27" "QCOW2"

# AlmaLinux Templates
echo "=== ALMALINUX TEMPLATES ==="
register_template "AlmaLinux-9" "https://repo.almalinux.org/almalinux/9/cloud/x86_64/images/AlmaLinux-9-GenericCloud-latest.x86_64.qcow2" "27" "QCOW2"
register_template "AlmaLinux-8" "https://repo.almalinux.org/almalinux/8/cloud/x86_64/images/AlmaLinux-8-GenericCloud-latest.x86_64.qcow2" "27" "QCOW2"

# CentOS Stream Templates
echo "=== CENTOS STREAM TEMPLATES ==="
register_template "CentOS-Stream-9" "https://cloud.centos.org/centos/9-stream/x86_64/images/CentOS-Stream-GenericCloud-9-latest.x86_64.qcow2" "27" "QCOW2"
register_template "CentOS-Stream-8" "https://cloud.centos.org/centos/8-stream/x86_64/images/CentOS-Stream-GenericCloud-8-latest.x86_64.qcow2" "27" "QCOW2"

# OpenSUSE Templates
echo "=== OPENSUSE TEMPLATES ==="
register_template "OpenSUSE-Leap-15.5" "https://download.opensuse.org/repositories/Cloud:/Images:/Leap_15.5/images/openSUSE-Leap-15.5-Minimal-VM.x86_64-Cloud.qcow2" "73" "QCOW2"
register_template "OpenSUSE-Leap-15.4" "https://download.opensuse.org/repositories/Cloud:/Images:/Leap_15.4/images/openSUSE-Leap-15.4-Minimal-VM.x86_64-Cloud.qcow2" "73" "QCOW2"

# Oracle Linux Templates
echo "=== ORACLE LINUX TEMPLATES ==="
register_template "Oracle-Linux-9" "https://yum.oracle.com/templates/OracleLinux/OL9/u5/x86_64/OL9U5_x86_64-kvm-b259.qcow2" "134" "QCOW2"
register_template "Oracle-Linux-8" "https://yum.oracle.com/templates/OracleLinux/OL8/u10/x86_64/OL8U10_x86_64-kvm-b258.qcow2" "134" "QCOW2"

# Fedora Templates
echo "=== FEDORA TEMPLATES ==="
register_template "Fedora-39" "https://download.fedoraproject.org/pub/fedora/linux/releases/39/Cloud/x86_64/images/Fedora-Cloud-Base-39-1.5.x86_64.qcow2" "175" "QCOW2"
register_template "Fedora-38" "https://download.fedoraproject.org/pub/fedora/linux/releases/38/Cloud/x86_64/images/Fedora-Cloud-Base-38-1.6.x86_64.qcow2" "175" "QCOW2"

# Windows Templates (Evaluation versions)
echo "=== WINDOWS TEMPLATES ==="
# Note: Download these manually from Microsoft Evaluation Center and upload to your server
echo "# Download Windows Server evaluations from:"
echo "# Windows Server 2025: https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2025"
echo "# Windows Server 2022: https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2022"
echo "# Windows Server 2019: https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2019"
echo "# Windows Server 2016: https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2016"
echo "# Windows 11: https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise"
echo "# Windows 10: https://www.microsoft.com/en-us/evalcenter/evaluate-windows-10-enterprise"
echo ""
echo "# After downloading, upload to your web server and register with these commands:"
echo "# register_template \"Windows-Server-2025-Eval\" \"https://your-server.com/windows-server-2025-eval.iso\" \"91\" \"ISO\""
echo "# register_template \"Windows-Server-2022-Eval\" \"https://your-server.com/windows-server-2022-eval.iso\" \"91\" \"ISO\""
echo "# register_template \"Windows-Server-2019-Eval\" \"https://your-server.com/windows-server-2019-eval.iso\" \"70\" \"ISO\""
echo "# register_template \"Windows-Server-2016-Eval\" \"https://your-server.com/windows-server-2016-eval.iso\" \"69\" \"ISO\""
echo "# register_template \"Windows-11-Enterprise\" \"https://your-server.com/windows-11-enterprise.iso\" \"159\" \"ISO\""
echo "# register_template \"Windows-10-Enterprise\" \"https://your-server.com/windows-10-enterprise.iso\" \"159\" \"ISO\""

# FreeBSD Templates
echo "=== FREEBSD TEMPLATES ==="
register_template "FreeBSD-14.1" "https://download.freebsd.org/releases/VM-IMAGES/14.1-RELEASE/amd64/Latest/FreeBSD-14.1-RELEASE-amd64.qcow2.xz" "111" "QCOW2"
register_template "FreeBSD-13.3" "https://download.freebsd.org/releases/VM-IMAGES/13.3-RELEASE/amd64/Latest/FreeBSD-13.3-RELEASE-amd64.qcow2.xz" "111" "QCOW2"

# OpenBSD Templates  
echo "=== OPENBSD TEMPLATES ==="
register_template "OpenBSD-7.4" "https://cdn.openbsd.org/pub/OpenBSD/7.4/amd64/install74.img" "112" "RAW"

# NetBSD Templates
echo "=== NETBSD TEMPLATES ==="
register_template "NetBSD-10.0" "https://cdn.netbsd.org/pub/NetBSD/NetBSD-10.0/images/NetBSD-10.0-amd64.img.gz" "113" "RAW"

# Alpine Linux Templates
echo "=== ALPINE LINUX TEMPLATES ==="
register_template "Alpine-Linux-3.19" "https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/cloud/alpine-cloud-3.19.1-x86_64-uefi.qcow2" "175" "QCOW2"
register_template "Alpine-Linux-3.18" "https://dl-cdn.alpinelinux.org/alpine/v3.18/releases/cloud/alpine-cloud-3.18.6-x86_64-uefi.qcow2" "175" "QCOW2"

# Arch Linux Templates
echo "=== ARCH LINUX TEMPLATES ==="
register_template "Arch-Linux" "https://geo.mirror.pkgbuild.com/images/latest/Arch-Linux-x86_64-cloudimg.qcow2" "175" "QCOW2"

# Clear Linux Templates
echo "=== CLEAR LINUX TEMPLATES ==="
register_template "Clear-Linux" "https://download.clearlinux.org/releases/current/clear/clear-cloudguest.img.xz" "175" "QCOW2"

# NixOS Templates
echo "=== NIXOS TEMPLATES ==="
register_template "NixOS-23.11" "https://channels.nixos.org/nixos-23.11/latest-nixos-x86_64-linux.ova" "175" "OVA"

# Kali Linux Templates
echo "=== KALI LINUX TEMPLATES ==="
register_template "Kali-Linux-2024.1" "https://kali.download/cloud-images/kali-2024.1/kali-linux-2024.1-cloud-amd64.tar.xz" "60" "QCOW2"

# Container-Optimized Templates
echo "=== CONTAINER-OPTIMIZED TEMPLATES ==="
register_template "Flatcar-Container-Linux" "https://stable.release.flatcar-linux.net/amd64-usr/current/flatcar_production_qemu_image.img.bz2" "175" "QCOW2"
register_template "Fedora-CoreOS" "https://builds.coreos.fedoraproject.org/prod/streams/stable/builds/39.20240128.3.0/x86_64/fedora-coreos-39.20240128.3.0-qemu.x86_64.qcow2.xz" "175" "QCOW2"

# Cloud-Native Templates
echo "=== CLOUD-NATIVE TEMPLATES ==="
register_template "RancherOS-2" "https://github.com/rancher/os2/releases/download/v2.0.0-alpha1/rancheros-2.0.0-alpha1-amd64.iso" "175" "ISO"

# Specialized Templates
echo "=== SPECIALIZED TEMPLATES ==="
register_template "pfSense-CE" "https://files.netgate.com/file/pfsense-ce-memstick/2.7.2/pfSense-CE-memstick-2.7.2-RELEASE-amd64.img.gz" "175" "RAW"
register_template "OPNsense" "https://mirror.ams1.nl.leaseweb.net/opnsense/releases/24.1/OPNsense-24.1-nano-amd64.img.bz2" "175" "RAW"

echo ""
echo "=== TEMPLATE REGISTRATION COMPLETE ==="
echo "Check template download progress in CloudStack web UI under Templates"
echo "Templates will change from 'Not Ready' to 'Ready' once downloaded"
echo ""
echo "Common OS Type IDs:"
echo "25 = Ubuntu"
echo "27 = CentOS/RHEL/Rocky/Alma"
echo "60 = Debian"
echo "69 = Windows Server 2016"
echo "70 = Windows Server 2019"
echo "91 = Windows Server 2022/2025"
echo "73 = OpenSUSE"
echo "111 = FreeBSD"
echo "112 = OpenBSD"
echo "113 = NetBSD"
echo "134 = Oracle Linux"
echo "159 = Windows Desktop (10/11)"
echo "175 = Other Linux (Fedora/Alpine/Arch/etc)"
