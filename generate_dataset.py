import os.path as osp

from data_processing.config import *
from data_processing.extract_features import find_data_files, read_pcap

if __name__ == '__main__':

    # test packet extraction using cicids17

    dnames, fnames = find_data_files(cicids17pcaps)
    pcap_fnames = []
    for dname,fname_list in zip(dnames, fnames):
        dfs = [osp.join(dname, fname) for fname in fname_list]
        pcap_fnames.extend([osp.join(cicids17pcaps, df) for df in dfs])
    print(len(pcap_fnames), pcap_fnames[0])
    features = read_pcap(pcap_fnames[0])
    print(len(features))
    print(features[0])