import argparse
from pathlib import Path

PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1":"pcap (little-endian)",
    b"\xa1\xb2\xc3\xd4":"pcap (big-endian)",
    b"\x0a\x0d\x0d\x0a":"pcapng"
}

def inspect(path):

    p=Path(path)

    if not p.exists():
        print("File not found.")
        return

    size=p.stat().st_size

    with open(p,"rb") as f:
        magic=f.read(4)

    typ=PCAP_MAGIC.get(magic,"unknown")

    print()
    print("MicroShark")
    print("="*40)
    print("File      :",p.name)
    print("Format    :",typ)
    print("Size      :",size,"bytes")
    print()

    if typ=="unknown":
        print("Unsupported capture.")
    else:
        print("Capture recognized.")
        print("Protocol decoding arrives in v1.1")

def main():

    parser=argparse.ArgumentParser(
        prog="microshark",
        description="Tiny packet capture inspector"
    )

    parser.add_argument("capture",help="pcap/pcapng file")

    args=parser.parse_args()

    inspect(args.capture)
