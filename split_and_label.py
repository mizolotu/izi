import os.path as osp
import os, shutil
import argparse as arp

from subprocess import Popen, DEVNULL
from common import data
from common.data import find_data_files, split_by_label
from common.utils import parse_fname_ip, clean_dir
from config import *

if __name__ == '__main__':

    # process args

    parser = arp.ArgumentParser(description='Generate datasets')
    parser.add_argument('-l', '--labeler', help='Labeler', default='label_cicids17_short')
    args = parser.parse_args()

    # import labeler

    labeler = getattr(data, args.labeler)

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

    # loop through input data

    print('Splitting into episode intervals:')

    dnames, fnames = find_data_files(raw_dir)
    for dname, fname_list in zip(dnames, fnames):
        idfs = [osp.join(dname, fname) for fname in fname_list]
        input_fnames = [osp.join(raw_dir, df) for df in idfs]
        output_dirs = [osp.join(spl_dir, parse_fname_ip(fname)) for fname in fname_list]
        for input_fname, output_dir in zip(input_fnames, output_dirs):
            print('Splitting {0}'.format(input_fname))
            if not osp.isdir(output_dir):
                os.mkdir(output_dir)
            output_fname = osp.join(output_dir, 'cap')
            p = Popen(['editcap', '-i', str(episode_duration), input_fname, output_fname], stdout=DEVNULL, stderr=DEVNULL)
            p.wait()

    print('Splitting based on the attack label:')

    dnames, fnames = find_data_files(spl_dir)
    for dname, fname_list in zip(dnames, fnames):
        idfs = [osp.join(dname, fname) for fname in fname_list]
        input_fnames = [osp.join(spl_dir, df) for df in idfs]
        for input_fname in input_fnames:
            print('Splitting {0}'.format(input_fname))
            split_by_label(input_fname, labeler)

    # all good

    print('All good!')