import os.path as osp
import os

from subprocess import Popen, DEVNULL
from common.data import find_data_files
from common.utils import parse_fname_ip
from config import *

if __name__ == '__main__':

    # create output directory if needed

    if not osp.isdir(spl_dir):
        os.mkdir(spl_dir)

    # loop through input data

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

    # all good

    print('All good!')