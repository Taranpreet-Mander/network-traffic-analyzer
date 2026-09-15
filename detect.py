from collections import defaultdict
from scapy.all import IP, TCP

# very simple "is anything sus" checks. not real detection, just
# obvious stuff a beginner can spot. thresholds are guesses (TODO tune)

PORTSCAN_PORT_THRESHOLD = 20   # one ip hitting this many different ports
SYN_FLOOD_THRESHOLD = 50       # this many bare SYNs from one ip


def run(packets):
    print("===== simple detections =====")

    ports_per_src = defaultdict(set)
    syn_only = defaultdict(int)

    for pkt in packets:
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            src = pkt[IP].src
            ports_per_src[src].add(int(pkt[TCP].dport))

            # SYN set but ACK not set = a connection attempt (not a reply)
            flags = pkt[TCP].flags
            if (flags & 0x02) and not (flags & 0x10):
                syn_only[src] += 1

    findings = []

    for src, ports in ports_per_src.items():
        if len(ports) >= PORTSCAN_PORT_THRESHOLD:
            findings.append(
                f"possible port scan from {src} - touched {len(ports)} different ports"
            )

    for src, n in syn_only.items():
        if n >= SYN_FLOOD_THRESHOLD:
            findings.append(
                f"lots of SYN packets from {src} ({n}) - could be a scan or SYN flood"
            )

    if findings:
        for f in findings:
            print(f"  [!] {f}")
    else:
        print("  nothing obvious flagged (that doesnt mean the traffic is clean!)")

    # TODO: dns tunneling check (loads of weird long dns queries)
    # TODO: plaintext http creds? maybe too much for now
