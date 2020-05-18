import os.path as osp
import numpy as np

from data_processing.config import *

"""
Label each packet in the datasets based on the event description provided
"""

def label_cicids17(timestamp, src_ip, dst_ip, src_port, dst_port):
    return

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