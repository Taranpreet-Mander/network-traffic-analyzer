from collections import Counter
from scapy.all import IP, IPv6, TCP, UDP, ICMP

# common ports so the output is readable instead of just numbers
PORT_NAMES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp", 80: "http", 110: "pop3",
    143: "imap", 443: "https", 445: "smb", 3389: "rdp", 8080: "http-alt",
}


def compute(packets):
    protos = Counter()
    src_ips = Counter()
    dst_ports = Counter()
    total_bytes = 0

    for pkt in packets:
        total_bytes += len(pkt)

        # grab the ip (v4 or v6)
        if pkt.haslayer(IP):
            src_ips[pkt[IP].src] += 1
        elif pkt.haslayer(IPv6):
            src_ips[pkt[IPv6].src] += 1

        # figure out the protocol + dest port
        if pkt.haslayer(TCP):
            protos["TCP"] += 1
            dst_ports[int(pkt[TCP].dport)] += 1
        elif pkt.haslayer(UDP):
            protos["UDP"] += 1
            dst_ports[int(pkt[UDP].dport)] += 1
        elif pkt.haslayer(ICMP):
            protos["ICMP"] += 1
        else:
            protos["other"] += 1

    return {
        "count": len(packets),
        "bytes": total_bytes,
        "protos": protos,
        "src_ips": src_ips,
        "dst_ports": dst_ports,
    }


def human_size(n):
    # quick and dirty byte formatter
    for unit in ["B", "KB", "MB", "GB"]:
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def print_report(s, top=10):
    print("===== traffic summary =====")
    print(f"packets: {s['count']}")
    print(f"total size: {human_size(s['bytes'])}")

    print("\nprotocols:")
    for name, c in s["protos"].most_common():
        print(f"  {name:6} {c}")

    print(f"\ntop {top} talkers (source ip):")
    for ip, c in s["src_ips"].most_common(top):
        print(f"  {ip:22} {c} packets")

    print(f"\ntop {top} destination ports:")
    for port, c in s["dst_ports"].most_common(top):
        name = PORT_NAMES.get(port, "?")
        print(f"  {port:<6} {name:9} {c}")
