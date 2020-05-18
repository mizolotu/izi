import os.path as osp

from data_processing.config import *
from data_processing.extract_features import find_data_files, read_pcap

if __name__ == '__main__':

    # test packet extraction using cicids17

    dnames, fnames = find_data_files(cicids17pcaps, postfix='pcap')
    pcap_fnames = []
    for dname,fname_list in zip(dnames, fnames):
        dfs = osp.join(dname, fname_list)
        pcap_fnames.append(osp.join(cicids17pcaps, dfs))
    print(len(pcap_fnames))
    features = read_pcap(pcap_fnames[0])
    print(features[0])
    print(len(features))