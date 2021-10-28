import os
import os.path as osp
import numpy as np
import argparse as arp

from common.plot import plot_and_save
from config import *

if __name__ == '__main__':

    parser = arp.ArgumentParser(description='Plot ROC')
    parser.add_argument('-a', '--attacks', help='Attacks labels', nargs='+', default=['0,1', '0,2', '0,3'])
    #parser.add_argument('-m', '--models', help='Models used for detection', nargs='+', default=['mlp', 'cnn', 'rnn'])
    parser.add_argument('-m', '--models', help='Models used for detection', nargs='+', default=['aen', 'som', 'bgn'])
    #parser.add_argument('-l', '--labels', help='Labels used for model training', nargs='+', default=['0,1,2,3'])
    parser.add_argument('-l', '--labels', help='Labels used for model training', nargs='+', default=['0'])
    #parser.add_argument('-x', '--xlim', help='X limit', default=0.01, type=float)
    parser.add_argument('-x', '--xlim', help='X limit', default=1, type=float)

    args = parser.parse_args()

    colors = ['royalblue', 'firebrick', 'seagreen']
    dashes = ['-', '--', ':', '.-']
    model_attacks = {
        '1': 'DDoS',
        '2': 'Web',
        '3': 'Botnet'
    }

    for label in os.listdir(ids_results_dir):

        if label in args.attacks:

            # prepare data

            data = []
            names = []
            models_path = osp.join(ids_results_dir, label)
            models = sorted(os.listdir(models_path))
            model_names = []
            cs = []
            cs_sorted = []
            ds = []
            ds_sorted = []
            attack_labels_str = []
            ls = []
            ws = []
            models_ = []

            cd_count = 0
            for m in models:

                spl = m.split('_')
                train_labels = spl[-2]

                if train_labels in args.labels:

                    m_type = spl[0]
                    if m_type in args.models:

                        m_type = m_type.upper()

                        models_.append(m)
                        ls.append(m_type)
                        cs.append(colors[cd_count])
                        ds.append(dashes[cd_count])
                        cd_count += 1
                        model_names.append(m_type)

            m_idx = sorted(range(len(model_names)), key=lambda k: model_names[k])
            for idx in m_idx:
                model_path = osp.join(models_path, models_[idx])
                if osp.isdir(model_path) and roc_fname in os.listdir(model_path):
                    roc_path = osp.join(model_path, roc_fname)
                    roc = np.genfromtxt(roc_path, dtype=float, delimiter=' ')
                    x = roc[:, 0]
                    y = roc[:, 1]
                    data.append([x, y])
                    names.append(model_names[idx])
                    cs_sorted.append(cs[idx])
                    ds_sorted.append(ds[idx])

            # save results

            fig_fname = '{0}/{1}_{2}'.format(roc_dir, label, '_'.join(args.labels))
            plot_and_save(fig_fname, names, data, cs_sorted, ds_sorted, xlabel='FPR', ylabel='TPR', xrange=[0, args.xlim], yrange=[0, 1])