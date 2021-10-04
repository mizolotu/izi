import os.path as osp

from common.data import find_data_files, remove_flags
from config import *

if __name__ == '__main__':
    dnames, fnames = find_data_files(spl_dir)
    uflags, uflag_counts = [], []
    for dname, fname_list in zip(dnames, fnames):
        print(dname)
        idfs = [osp.join(dname, fname) for fname in fname_list]
        input_fnames = [osp.join(spl_dir, input_fname) for input_fname in idfs if not input_fname.endswith('tmp')]
        for input_f in input_fnames:
            print(input_f)
            remove_flags(input_f, 3)