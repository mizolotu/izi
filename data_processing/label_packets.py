import os.path as osp
from datetime import datetime
from data_processing.config import *

"""
Label each packet in the datasets based on the event description provided
"""

def label_cicids17(timestamp, src_ip, dst_ip):
    timestamp = datetime.fromtimestamp(timestamp)
    date = timestamp.strftime('%d%m')
    if (src_ip == '18.219.211.138' or dst_ip == '18.219.211.138') and date == '1502':  # DoS-GoldenEye
        label = 1
    elif (src_ip == '18.217.165.70' or dst_ip == '18.217.165.70') and date == '1502':  # DoS-Slowloris
        label = 2
    elif (src_ip == '18.219.193.20' or dst_ip == '18.219.193.20') and date == '1602':  # DoS-Hulk
        label = 3
    elif (src_ip == '18.218.115.60' or dst_ip == '18.218.115.60') and date in ['2202', '2302']:  # BruteForce-Web
        label = 4
    elif (src_ip == '18.219.211.138' or dst_ip == '18.219.211.138') and date == '0203':  # Botnet attack
        label = 5
    else:
        label = 0
    return label

def label_unswnb15(timestamp, src_ip, dst_ip, src_port, dst_port):
    return

def create_labeler(pcap_fname):
    dir_path = osp.dirname(osp.realpath(pcap_fname))
    if dir_path in cicids17pcaps or cicids17pcaps in dir_path:
        labeler = label_cicids17
    elif dir_path in unswnb15pcaps or unswnb15pcaps in dir_path:
        labeler = label_unswnb15
    else:
        print('Unknown dataset. What is going on?')
        labeler = lambda timestamp, src_ip, dst_ip, src_port, dst_port: 0
    return labeler