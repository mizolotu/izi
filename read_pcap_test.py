import pcap, sys

from time import time
from common.data import read_pkt_faster

if __name__ == '__main__':
    fnames = [
        'data/spl/172.31.69.10/cap_03547_20180215221650',
        'data/spl/172.31.69.11/cap_01750_20180215181757',
        'data/spl/172.31.69.12/cap_03268_20180301213215',
        'data/spl/172.31.69.13/cap_00053_20180301161053',
        'data/spl/172.31.69.14/cap_00070_20180301142549',
        'data/spl/172.31.69.15/cap_00911_20180301162214',
        'data/spl/172.31.69.16/cap_00581_20180215154148',
        'data/spl/172.31.69.17/cap_03522_20180301220613',
        'data/spl/172.31.69.18/cap_02858_20180301204002',
        'data/spl/172.31.69.19/cap_00077_20180223142706',
        'data/spl/172.31.69.20/cap_03644_20180215223017',
        'data/spl/172.31.69.21/cap_00951_20180301162715',
        'data/spl/172.31.69.22/cap_01154_20180301165202',
        'data/spl/172.31.69.23/cap_03505_20180215221126',
        'data/spl/172.31.69.24/cap_00078_20180223142725',
        'data/spl/172.31.69.25/cap_03903_20180302232803',
        'data/spl/172.31.69.26/cap_03297_20180215214421',
        'data/spl/172.31.69.27/cap_07902_20180222080735',
        'data/spl/172.31.69.28/cap_03082_20180215211503',
        'data/spl/172.31.69.29/cap_01036_20180301163444',
        'data/spl/172.31.69.30/cap_00606_20180215154406',
        'data/spl/172.31.69.4/cap_00969_20180223162613',
        'data/spl/172.31.69.5/cap_03840_20180215225625',
        'data/spl/172.31.69.6/cap_03455_20180301215713',
        'data/spl/172.31.69.7/cap_02782_20180301203020',
        'data/spl/172.31.69.8/cap_03202_20180215213111',
        'data/spl/172.31.69.9/cap_03343_20180215215005'
    ]
    if len(sys.argv) == 2:
        fnames = [sys.argv[1] + fname for fname in fnames]

    pkts = []
    for fname in fnames:
        sniffer = pcap.pcap(name=fname)
        while True:
            try:
                ts, raw = next(sniffer)
                pkts.append(raw)
            except:
                break

    t0 = time()
    [read_pkt_faster(raw) for raw in pkts]
    print(f'Time elapsed to process {len(pkts)} packets: {time() - t0}')