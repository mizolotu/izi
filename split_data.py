import os.path as osp
import os, shutil

from time import time
from subprocess import Popen, DEVNULL
from common.data import find_data_files
from common.utils import parse_fname_ip
from config import *

if __name__ == '__main__':

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

    # print time elapsed

    print(f'\nCompleted in {(time() - tstart) / 60} minutes!')