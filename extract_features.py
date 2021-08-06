import argparse as arp
import os.path as osp
import os, sys

from time import time
from common.data import find_data_files, extract_flow_features
from common.utils import isint, clean_dir
from pathlib import Path
from config import *

if __name__ == '__main__':

    # parse args

    parser = arp.ArgumentParser(description='Generate datasets')
    parser.add_argument('-s', '--stepval', help='Time step', type=float)
    parser.add_argument('-S', '--stepdistr', help='Time step distribution', nargs='+', default=[0.0, 1.0, 0.001, 3.0], type=float)
    args = parser.parse_args()

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
        else:
            os.mkdir(_dir)

    # input data

    dnames, fnames = find_data_files(spl_dir)

    # metainfo

    meta_f = osp.join(data_dir, meta_fname)

    # process data

    tstart = time()

    dcount = 0
    ttotal = 0
    ntotal = 0
    for dname, fname_list in zip(dnames, fnames):
        dcount += 1
        idfs = [osp.join(dname, fname) for fname in fname_list]
        input_fnames = [osp.join(spl_dir, input_fname) for input_fname in idfs]
        input_fnames = [item for item in input_fnames if item.split('_')[-1].split(':')[0] == 'label' and isint(item.split('_')[-1].split(':')[1])]
        fcount = 0
        for input_f in input_fnames:
            fcount += 1
            label = input_f.split('_')[-1].split(':')[1]
            features_label_dir = osp.join(features_dir, label)
            stats_label_dir = osp.join(stats_dir, label)
            for _dir in [features_label_dir, stats_label_dir]:
                if not osp.isdir(_dir):
                    os.mkdir(_dir)
            output_f = osp.join(features_label_dir, dname)
            stats_f = osp.join(stats_label_dir, dname)
            fsize = Path(input_f).stat().st_size
            telapsed = extract_flow_features(input_f, output_f, stats_f, meta_f, label=label, tstep=step, stages=stages, splits=splits)
            if telapsed is not None:
                ttotal += telapsed
                ntotal += 1
                print('Directory: {0}/{1}, file: {2}/{3}, size: {4}, input: {5}, time per flow: {6}'.format(
                    dcount, len(dnames), fcount, len(input_fnames), fsize, input_f, ttotal / ntotal)
                )

    # print time elapsed

    print(f'\nCompleted in {time() - tstart // 60} minutes!')