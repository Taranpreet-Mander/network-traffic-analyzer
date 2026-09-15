# network traffic analyzer

a little python tool i wrote to read a pcap (packet capture) file and tell you whats going on in it - how many packets, what protocols, who's talking the most, and a couple of simple "is anything sus" checks like port scans.

made this to get better at python AND at understanding network traffic at the same time. still pretty basic but it works.

## what it does

- counts packets + total size
- breaks down protocols (tcp / udp / icmp / other)
- top talkers (which source ips send the most)
- top destination ports (with names for the common ones)
- simple detections:
  - port scan (one ip hitting loads of different ports)
  - lots of bare SYN packets (scan / syn flood-ish)

## how to run

need python 3 and scapy:

```bash
pip install -r requirements.txt
python analyzer.py yourcapture.pcap
```

options:

```bash
python analyzer.py yourcapture.pcap --top 20   # show top 20 instead of 10
```

## example

see [sample_output.txt](sample_output.txt) for a full run. short version:

```
protocols:
  TCP    80
  UDP    30
  ICMP   1

===== simple detections =====
  [!] possible port scan from 10.0.0.66 - touched 60 different ports
```

## where do i get a pcap to test with?

- capture your own with wireshark (or `tcpdump`) and save as .pcap
- wireshark has sample captures: https://wiki.wireshark.org/SampleCaptures
- i tested it by making a fake capture in scapy with a port scan in it

## how its put together

kept it in a few small files instead of one big one:

- `analyzer.py` - the main script, handles the args and ties it together
- `read_pcap.py` - loads the file
- `stats.py` - does the counting + prints the summary
- `detect.py` - the simple detection checks

## stuff i want to add

- [ ] live capture (sniff off the network) instead of only files - needs npcap on windows, havent done it yet
- [ ] dns tunneling detection (weird long dns queries)
- [ ] export the report to a file / json
- [ ] the "top ports" output looks ugly when theres a scan (shows ports 1,2,3...), maybe group those
- [ ] tests

## notes

for learning / my own lab use. dont sniff networks you dont have permission to.

MIT license.
