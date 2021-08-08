import os.path as osp
import os, shutil
import argparse as arp

from time import time
from subprocess import Popen, DEVNULL
from common import data
from common.data import find_data_files, split_by_label
from common.utils import parse_fname_ip
from config import *

if __name__ == '__main__':

    # process args

    parser = arp.ArgumentParser(description='Generate datasets')
    parser.add_argument('-l', '--labeler', help='Labeler', default='label_cicids17_short')
    args = parser.parse_args()

    # import labeler

    labeler = getattr(data, args.labeler)

    # metainfo

    meta_f = osp.join(data_dir, meta_fname)

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

    print('\nSplitting into time intervals:\n')

    dnames, fnames = find_data_files(raw_dir)
    dcount = 0
    for dname, fname_list in zip(dnames, fnames):
        dcount += 1
        print('Splitting files in directory {0}/{1}: {2}'.format(dcount, len(dnames), dname))
        idfs = [osp.join(dname, fname) for fname in fname_list]
        input_fnames = [osp.join(raw_dir, df) for df in idfs]
        output_dirs = [osp.join(spl_dir, parse_fname_ip(fname)) for fname in fname_list]
        for input_fname, output_dir in zip(input_fnames, output_dirs):
            if not osp.isdir(output_dir):
                os.mkdir(output_dir)
            output_fname = osp.join(output_dir, 'cap')
            p = Popen(['editcap', '-i', str(episode_duration), input_fname, output_fname], stdout=DEVNULL, stderr=DEVNULL)
            p.wait()

    # split each time intervals based on the label

    print('\nSplitting based on the attack label:\n')

    dnames, fnames = find_data_files(spl_dir)
    dcount = 0
    for dname, fname_list in zip(dnames, fnames):
        dcount += 1
        print('Splitting files in directory {0}/{1}: {2}'.format(dcount, len(dnames), dname))
        idfs = [osp.join(dname, fname) for fname in fname_list]
        input_fnames = [osp.join(spl_dir, df) for df in idfs]
        for input_f in input_fnames:
            split_by_label(input_f, labeler, meta_f, nulify_dscp=True)

    # print time elapsed

    print(f'\nCompleted in {(time() - tstart) // 3600} hours!')