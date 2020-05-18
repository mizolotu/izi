import pcap, os
import numpy as np
import os.path as osp

from socket import inet_ntop, AF_INET
from kaitaistruct import KaitaiStream, BytesIO
from nltk import ngrams, FreqDist

from data_processing.read_pcaps import EthernetFrame
from data_processing.label_packets import create_labeler
from data_processing.config import *

def ngram(str, n):
    x = [int(item) for item in str.split(',')]
    freqs = np.zeros(256**n)
    v = 256 ** np.arange(n)[::-1]
    grams = ngrams(x, n)
    fd = FreqDist()
    fd.update(grams)
    for key in fd.keys():
        freqs[np.dot(key, v)] = fd[key]
    return freqs

def decode_tcp_flags_value(value):
    b = '{0:b}'.format(value)[::-1]
    positions = '.'.join([str(i) for i in range(len(b)) if b[i] == '1'])
    return positions

def read_tcp_packet(body):
    src_port = body.body.body.src_port
    dst_port = body.body.body.dst_port
    payload = body.body.body.body
    flags = body.body.body.b13
    window = body.body.body.window_size
    return src_port, dst_port, len(payload), payload.decode('ascii', 'ignore'), decode_tcp_flags_value(flags), window

def read_udp(body):
    src_port = body.body.body.src_port
    dst_port = body.body.body.dst_port
    payload = body.body.body.body
    return src_port, dst_port, len(payload), payload.decode('ascii', 'ignore')

def read_ip_pkt(body):
    src_ip = inet_ntop(AF_INET, body.src_ip_addr)
    dst_ip = inet_ntop(AF_INET, body.dst_ip_addr)
    read_size = body.read_len
    proto = body.protocol
    if proto == 6:
        src_port, dst_port, plen, payload, flags, window = read_tcp_packet(body)
    elif proto == 17:
        src_port, dst_port, plen, payload = read_tcp_packet(body)
        flags = ''
        window = 0
    else:
        # here we can extract features for protocols other than tcp and udp, but so far we just init them with zeros
        src_port = 0
        dst_port = 0
        plen = 0
        payload = ''
        flags = ''
        window = 0
    return src_ip, dst_ip, src_port, dst_port, proto, read_size, plen, flags, window, payload

def read_pcap(pcap_fname, n=1): # n is the number of grams to extract from packet payloads
    reader = pcap.pcap(pcap_fname)
    count = 0
    features_and_labels = []
    labeler = create_labeler(pcap_fname)
    for timestamp, raw in reader:
        count += 1
        try:
            pkt = EthernetFrame(KaitaiStream(BytesIO(raw)))
            if pkt.ether_type.value == 2048:
                frame_size = pkt.body.total_length
                src_ip, dst_ip, src_port, dst_port, proto, plen, flags, window, payload = read_ip_pkt(pkt.body)
                payload_grams = ngram(payload, n)

                # features

                x = [
                    count, # 0
                    timestamp, # 1
                    src_ip, # 2
                    dst_ip, # 3
                    src_port, # 4
                    dst_port, # 5
                    proto, # 6
                    frame_size, # 7
                    flags, # 8
                    window, # 9
                    plen, # 10
                    payload_grams # 11..266
                ]

                # label

                y = labeler(timestamp, src_ip, dst_ip, src_port, dst_port) # 267

                features_and_labels.append(','.join([*[str(item) for item in x], y]))
            elif pkt.ether_type.value == 2054:
                # ARP packet analysis can be here, but we for now focus on IP traffic
                pass
        except:
            pass
    return features_and_labels

def find_data_files(dir, prefix='', postfix=''):
    data_files = []
    data_dirs = []
    for d in os.listdir(dir):
        dp = osp.join(dir, d)
        if osp.isdir(dp):
            data_dirs.append(d)
            data_files.append([])
            for f in os.listdir(dp):
                fp = osp.join(dp, f)
                print(fp)
                if osp.isfile(fp) and fp.startswith(osp.join(fp, prefix)) and fp.endswith(postfix):
                    data_files[-1].append(f)
    return data_dirs, data_files