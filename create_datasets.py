import argparse as arp
import os.path as osp
import os

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
        raise NotImplemented

    # clean output directory or create one if needed

    if osp.isdir(feature_dir):
        labels, _ = find_data_files(feature_dir)
        for label in labels:
            label_dir = osp.join(feature_dir, label)
            clean_dir(label_dir, postfix='')
    else:
        os.mkdir(feature_dir)

    # input data

    dnames, fnames = find_data_files(spl_dir)

    # metainfo

    meta_fname = 'metainfo.json'
    meta_fpath = osp.join(feature_dir, meta_fname)

    # process data

    dcount = 0
    for dname, fname_list in zip(dnames, fnames):
        dcount += 1
        idfs = [osp.join(dname, fname) for fname in fname_list]
        input_fnames = [osp.join(spl_dir, input_fname) for input_fname in idfs]
        input_fnames = [item for item in input_fnames if item.split('_')[-1].split(':')[0] == 'label' and isint(item.split('_')[-1].split(':')[1])]
        fcount = 0
        for input_fname in input_fnames:
            fcount += 1
            label = input_fname.split('_')[-1].split(':')[1]
            label_dir = osp.join(feature_dir, label)
            if not osp.isdir(label_dir):
                os.mkdir(label_dir)
            output_fname = osp.join(label_dir, dname)
            fsize = Path(input_fname).stat().st_size
            print('Directory: {0}/{1}, file: {2}/{3}, size: {4}, input: {5}'.format(dcount, len(dnames), fcount, len(input_fnames), fsize, input_fname))
            extract_flow_features(input_fname, output_fname, meta_fpath, label, step)