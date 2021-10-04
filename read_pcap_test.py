import os.path as osp
import numpy as np

from common.data import find_data_files, count_flags
from config import *

if __name__ == '__main__':
    dnames, fnames = find_data_files(spl_dir)
    uflags, uflag_counts = [], []
    for dname, fname_list in zip(dnames, fnames):
        print(dname)
        idfs = [osp.join(dname, fname) for fname in fname_list]
        input_fnames = [osp.join(spl_dir, input_fname) for input_fname in idfs]
        for input_f in input_fnames:
            uflags_, uflag_counts_ = count_flags(input_f)
            newf = False
            for f,c in zip(uflags_, uflag_counts_):
                if f not in uflags:
                    uflags.append(f)
                    uflag_counts.append(c)
                    newf = True
                else:
                    idx = uflags.index(f)
                    uflag_counts[idx] += c
            if newf:
                print('\n')
                idx = np.argsort(uflag_counts)[::-1]
                for i in idx:
                    print(f'{uflags[i]}: {uflag_counts[i]}')



