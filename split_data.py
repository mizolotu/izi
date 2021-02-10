import argparse as arp
import os.path as osp
import os

from subprocess import Popen, DEVNULL
from common.data import find_data_files
from common.utils import parse_fname_ip

if __name__ == '__main__':

    # parse args

    parser = arp.ArgumentParser(description='Split data')
    parser.add_argument('-i', '--input', help='Directory with input data', default='data/raw')
    parser.add_argument('-o', '--output', help='Directory for output data', default='data/spl')
    parser.add_argument('-s', '--step', help='Step size in seconds', default=60, type=float)
    parser.add_argument('-n', '--name', help='Output file name', default='cap')
    args = parser.parse_args()

    # create output directory if needed

    if not osp.isdir(args.output):
        os.mkdir(args.output)

    # loop through input data

    dnames, fnames = find_data_files(args.input)
    for dname, fname_list in zip(dnames, fnames):
        idfs = [osp.join(dname, fname) for fname in fname_list]
        input_fnames = [osp.join(args.input, df) for df in idfs]
        output_dirs = [osp.join(args.output, parse_fname_ip(fname)) for fname in fname_list]
        for input_fname, output_dir in zip(input_fnames, output_dirs):
            print('Splitting {0}'.format(input_fname))
            if not osp.isdir(output_dir):
                os.mkdir(output_dir)
            output_fname = osp.join(output_dir, args.name)
            p = Popen(['editcap', '-i', str(args.step), input_fname, output_fname], stdout=DEVNULL, stderr=DEVNULL)
            p.wait()

    # all good

    print('All good!')