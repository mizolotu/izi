import argparse as arp
import os.path as osp
import os

from common.data import find_data_files, extract_flow_features
from common import data
from pathlib import Path
from config import *

if __name__ == '__main__':

    parser = arp.ArgumentParser(description='Generate datasets')
    parser.add_argument('-l', '--labeler', help='Labeler', default='label_cicids17')
    parser.add_argument('-s', '--step', help='Time step', default=1, type=float)
    parser.add_argument('-e', '--exclude', help='Exclude days', default='20180220,20180221')
    args = parser.parse_args()

    # import labeler

    labeler = getattr(data, args.labeler)

    # create output directory if needed

    if not osp.isdir(feature_dir):
        os.mkdir(feature_dir)

    # input data

    dnames, fnames = find_data_files(spl_dir)

    # metainfo

    meta_fname = 'metainfo.json'

    # output fname pattern

    output_pattern = osp.join(feature_dir, '{0}')

    # exclude file names

    exclude_patterns = [aug_postfix]
    if ',' in args.exclude:
        exclude_patterns += args.exclude.split(',')

    # process data

    dcount = 0
    for dname, fname_list in zip(dnames, fnames):
        dcount += 1
        for exclude_pattern in exclude_patterns:
            fname_list = [fname for fname in fname_list if exclude_pattern not in fname]
        idfs = [osp.join(dname, fname) for fname in fname_list]
        input_fnames = [osp.join(spl_dir, df) for df in idfs]
        output_fname_patterns = [osp.join(output_pattern, dname) for fname in fname_list]
        meta_fpath = osp.join(feature_dir, meta_fname)
        fcount = 0
        for input_fname, output_fname in zip(input_fnames, output_fname_patterns):
            fcount += 1
            fsize = Path(input_fname).stat().st_size
            print('Directory: {0}/{1}, file: {2}/{3}, size: {4}, input: {5}'.format(dcount, len(dnames), fcount, len(input_fnames), fsize, input_fname))
            if fsize > fsize_min:
                extract_flow_features(input_fname, output_fname, meta_fpath, labeler, args.step)