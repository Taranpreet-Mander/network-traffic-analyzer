import argparse

import read_pcap
import stats
import detect


def main():
    ap = argparse.ArgumentParser(
        description="simple network traffic analyzer - reads a pcap and tells you whats in it"
    )
    ap.add_argument("pcap", help="path to the .pcap / .pcapng file")
    ap.add_argument("--top", type=int, default=10,
                    help="how many top talkers / ports to show (default 10)")
    args = ap.parse_args()

    print(f"[*] loading {args.pcap} ...")
    packets = read_pcap.load_pcap(args.pcap)
    if packets is None:
        return
    if len(packets) == 0:
        print("[!] no packets in that file?")
        return

    print(f"[*] loaded {len(packets)} packets\n")

    s = stats.compute(packets)
    stats.print_report(s, top=args.top)

    print()
    detect.run(packets)


if __name__ == "__main__":
    main()
