import argparse as arp
import os.path as osp
import os

from common.data import find_data_files, extract_flow_features
from common.data import label_cicids17 as labeler  # move this to args TO DO
from pathlib import Path

if __name__ == '__main__':

    parser = arp.ArgumentParser(description='Generate datasets')
    parser.add_argument('-i', '--input', help='Directory with input data', default='data/spl')
    parser.add_argument('-o', '--output', help='Directory for output data', default='data/features')
    parser.add_argument('-s', '--step', help='Polling time step', default=1, type=float)
    parser.add_argument('-e', '--exclude', help='Exclude days', default='20180220,20180221')
    parser.add_argument('-v', '--verbose', help='Verbose', default=True, type=bool)
    args = parser.parse_args()

    # create output directory if needed

    if not osp.isdir(args.output):
        os.mkdir(args.output)

    # input data

    dnames, fnames = find_data_files(args.input)

    # metainfo

    meta_fname = 'metainfo.json'

    # output fname pattern

    output_pattern = osp.join(args.output, '{0}')

    # exclude file names

    if ',' in args.exclude:
        exclude_patterns = args.exclude.split(',')
    else:
        exclude_patterns = []

    # process data

    dcount = 0
    for dname, fname_list in zip(dnames, fnames):
        dcount += 1
        for exclude_pattern in exclude_patterns:
            fname_list = [fname for fname in fname_list if exclude_pattern not in fname]
        idfs = [osp.join(dname, fname) for fname in fname_list]
        input_fnames = [osp.join(args.input, df) for df in idfs]
        #output_fname_patterns = [osp.join(output_pattern, '{0}_{1}'.format(dname, fname.split('_')[2])) for fname in fname_list]
        output_fname_patterns = [osp.join(output_pattern, dname) for fname in fname_list]
        meta_fpath = osp.join(args.output, meta_fname)
        fcount = 0
        for input_fname, output_fname in zip(input_fnames, output_fname_patterns):
            fcount += 1
            print('Directory: {0}/{1}, file: {2}/{3}, size: {4}, input: {5}, output: {6}'.format(dcount, len(dnames), fcount, len(input_fnames), Path(input_fname).stat().st_size, input_fname, output_fname))
            extract_flow_features(input_fname, output_fname, meta_fpath, args.step, labeler)