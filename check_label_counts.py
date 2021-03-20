import pandas, os
import os.path as osp
import numpy as np

from config import *

if __name__ == '__main__':
    profile_files = sorted([osp.join(spl_dir, item) for item in os.listdir(spl_dir) if osp.isfile(osp.join(spl_dir, item)) and item.endswith(csv_postfix)])
    maxs = []
    for profile_file in profile_files:
        vals = pandas.read_csv(profile_file, header=None).values
        fnames = vals[:, 0]
        counts = vals[:, 1:]
        profile_maxs = np.max(counts, axis=0)
        print(profile_file, profile_maxs)
        maxs.append(profile_maxs)
    maxs = np.max(maxs, axis=0)
    for i, m in enumerate(maxs):
        print('{0}: {1}'.format(i, m))

