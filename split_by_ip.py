import os.path as osp
import os, shutil
import argparse as arp

from time import time
from common.data import find_data_files, split_by_ip
from config import *

if __name__ == '__main__':

    # parse args

    parser = arp.ArgumentParser(description='Split data.')
    parser.add_argument('-d', '--dir', help='Directory name', default='Thursday-06-07-2017')
    parser.add_argument('-s', '--subnet', help='Subnet', default='192.168.10.')
    parser.add_argument('-e', '--exclude', help='Exclude IPs from the subnet',nargs='+', default=['192.168.10.1', '192.168.10.3', '192.168.10.255'])
    args = parser.parse_args()

    # create output directory if needed

    if not osp.isdir(spl_dir):
        os.mkdir(spl_dir)
    else:
        for item in os.listdir(spl_dir):
            path = osp.join(spl_dir, item)
            if osp.isfile(path):
                os.remove(path)
            elif osp.isdir(path):
                shutil.rmtree(path)
    tstart = time()

    # split into time intervals

    print('\nSplitting by ip:\n')

    dnames, fnames = find_data_files(raw_dir, args.dir)
    dcount = 0
    for dname, fname_list in zip(dnames, fnames):
        dcount += 1
        print('Splitting files in directory {0}/{1}: {2}'.format(dcount, len(dnames), dname))
        idfs = [osp.join(dname, fname) for fname in fname_list]
        output_dir = osp.join(raw_dir, dname)
        input_fnames = [osp.join(raw_dir, df) for df in idfs]
        for input_fname in input_fnames:
            split_by_ip(input_fname, output_dir, args.subnet, args.exclude)

    # print time elapsed

    print(f'\nCompleted in {(time() - tstart) / 60} minutes!')