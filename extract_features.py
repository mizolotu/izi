import argparse as arp
import os.path as osp
import os, sys, shutil

from time import time
from common import data
from common.data import find_data_files, split_by_label_and_extract_flow_features
from common.utils import isint, clean_dir
from pathlib import Path
from config import *

if __name__ == '__main__':

    # parse args

    parser = arp.ArgumentParser(description='Generate datasets')
    parser.add_argument('-s', '--stepval', help='Time step', type=float)
    parser.add_argument('-d', '--stepdistr', help='Time step distribution', nargs='+', default=[0.0, 1.0, 0.001, 3.0], type=float)
    parser.add_argument('-l', '--labeler', help='Labeler', default='label_cicids17_short')
    args = parser.parse_args()

    # import labeler

    labeler = getattr(data, args.labeler)

    # metainfo

    meta_f = osp.join(data_dir, meta_fname)

    # choose step value or distribution

    if args.stepval is not None:
        step = args.stepval
    elif args.stepdistr is not None and len(args.stepdistr) == 4:
        step = args.stepdistr
    else:
        print('You should provide either step value or distribution in form of list: [mu, std, min, max]')
        sys.exit(1)

    # clean output directories or create new ones if needed

    for _dir in [features_dir, stats_dir]:
        if osp.isdir(_dir):
            labels, _ = find_data_files(_dir)
            for label in labels:
                label_dir = osp.join(_dir, label)
                clean_dir(label_dir, postfix='')
                shutil.rmtree(label_dir)
        else:
            os.mkdir(_dir)

    # input data

    dnames, fnames = find_data_files(spl_dir)

    # metainfo fpath

    meta_f = osp.join(data_dir, meta_fname)

    # process data

    tstart = time()

    dcount = 0
    for dname, fname_list in zip(dnames, fnames):
        dcount += 1
        idfs = [osp.join(dname, fname) for fname in fname_list]
        input_fnames = [osp.join(spl_dir, input_fname) for input_fname in idfs if 'label' not in input_fname]
        fcount = 0
        ntotal = 0
        ttotal = 0
        for input_f in input_fnames:
            fcount += 1
            features_label_dir = osp.join(features_dir, '{0}')
            stats_label_dir = osp.join(stats_dir, '{0}')
            output_f = osp.join(features_label_dir, dname)
            stats_f = osp.join(stats_label_dir, dname)
            fsize = Path(input_f).stat().st_size
            nv, tt = split_by_label_and_extract_flow_features(input_f, features_dir, stats_dir, dname, meta_f, labeler=labeler, tstep=step, stages=stages, splits=splits)
            if nv > 0 and tt > 0:
                ttotal += tt
                ntotal += nv
        if ntotal > 0:
            print('Extracted features from {0} files of directory {1}/{2}: {3}, feature vectors: {4}, time per vector: {5}'.format(
                len(input_fnames), dcount, len(dnames), dname, ntotal, ttotal / ntotal)
            )
        else:
            print('Looks like no data have been found. Split the data first.')

    # print time elapsed

    print(f'\nCompleted in {(time() - tstart) / 3600} hours!')