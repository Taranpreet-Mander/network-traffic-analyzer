# notes

## why scapy

looked at a few options (dpkt, pyshark, scapy). went with scapy because most tutorials use it and rdpcap() reading a whole file is dead simple. pyshark needs tshark installed which was extra hassle.

## things i learned / got stuck on

- `pkt.haslayer(TCP)` is how you check what a packet is. took me a bit to realise a packet has "layers" (ether -> ip -> tcp).
- tcp flags are a bitfield. SYN is 0x02, ACK is 0x10. to find connection *attempts* i check SYN set but ACK not set. had to look this up.
- had to do `int(pkt[TCP].dport)` because scapy sometimes gives a weird flag/enum type and my Counter got confused.
- the port scan threshold (20 ports) is just a number i picked. real tools are smarter about it. TODO.

## testing

i dont have a proper unit test yet (TODO). for now i test by making a fake pcap in scapy that has an obvious port scan and checking the detection fires. it does.

## ideas if i keep going

- live sniffing (needs npcap on windows, admin rights)
- output to json so it could feed into something else (maybe into my SOC lab??)
- detect plaintext http / ftp passwords in the packets, that'd be a cool demo
