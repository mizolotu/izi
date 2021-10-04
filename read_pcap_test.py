import os.path as osp

from common.data import find_data_files, count_flags
from config import *

if __name__ == '__main__':
    dnames, fnames = find_data_files(spl_dir)
    uflags = []
    for dname, fname_list in zip(dnames, fnames):
        print(dname)
        idfs = [osp.join(dname, fname) for fname in fname_list]
        input_fnames = [osp.join(spl_dir, input_fname) for input_fname in idfs]
        for input_f in input_fnames:
            uflags_ = count_flags(input_f)
            newf = False
            for f in uflags_:
                if f not in uflags:
                    uflags.append(f)
                    newf = True
            if newf:
                print(uflags)


