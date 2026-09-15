from scapy.all import rdpcap


def load_pcap(path):
    # just read the whole file into memory. fine for small captures,
    # would be a problem for a huge one but im not there yet
    try:
        packets = rdpcap(path)
    except FileNotFoundError:
        print(f"[!] file not found: {path}")
        return None
    except Exception as e:
        # scapy throws different stuff for bad files, catch it all
        print(f"[!] couldnt read the pcap: {e}")
        return None
    return packets
