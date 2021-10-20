import os
import os.path as osp
import numpy as np
import argparse as arp

from common.plot import generate_line_scatter, plot_and_save
from config import *

if __name__ == '__main__':

    parser = arp.ArgumentParser(description='Plot ROC')
    parser.add_argument('-m', '--models', help='Models used for detection', nargs='+', default=['mlp'])
    parser.add_argument('-l', '--labels', help='Labels used for model training', nargs='+', default=['1', '2', '3', '1,2,3'])
    parser.add_argument('-a', '--attacks', help='Attacks labels', nargs='+', default=['1', '2', '3'])
    #parser.add_argument('-m', '--models', help='Models used for detection', nargs='+', default=['ae', 'som', 'mlp'])
    #parser.add_argument('-l', '--labels', help='Labels used for model training', nargs='+', default=['1,3'])
    #parser.add_argument('-a', '--attacks', help='Attacks labels', nargs='+', default=['2'])
    args = parser.parse_args()

    colors = ['royalblue', 'firebrick', 'seagreen']

    dashes = ['-', '--', ':', '-.']

    model_attacks = {
        '1': 'DDoS',
        '2': 'Web',
        '3': 'Botnet',
        '1,2,3': 'Baseline'
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

            for m in models:

                spl = m.split('_')
                train_labels = spl[-2]

                if train_labels in args.labels:

                    m_type = spl[0]
                    if m_type in args.models:

                        m_type = m_type.upper()

                        models_.append(m)
                        if train_labels in model_attacks.keys():
                            a_type = model_attacks[train_labels]
                        else:
                            a_type = None
                        ma_type = f'{m_type}_{a_type}'
                        if ma_type not in ls:
                            ls.append(ma_type)
                        a_idx = ls.index(ma_type)
                        cs.append(colors[a_idx])

                        w_size = spl[-1]
                        if w_size not in ws:
                            ws.append(w_size)
                        w_idx = ws.index(w_size)
                        ds.append(dashes[w_idx])

                        if a_type is not None:
                            model_name = f'{a_type} {m_type}, {w_size} sec.'
                        else:
                            model_name = f'{m_type}, {w_size} sec.'
                        model_names.append(model_name)
                        if train_labels not in attack_labels_str:
                            attack_labels_str.append(train_labels)

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

            # generate layout and traces

            fig_fname = '{0}/{1}_{2}'.format(roc_dir, label, '_'.join(attack_labels_str))
            plot_and_save(fig_fname, names, data, cs_sorted, ds_sorted, xlabel='False positive rate', ylabel='True positive rate', xrange=[0, 0.1], yrange=[0, 1])

            #traces, layout = generate_line_scatter(names, data, cs_sorted, ds_sorted, xlabel='FPR', ylabel='TPR', xrange=[0, 0.01], yrange=[0, 0.8])

            # save results

            #ftypes = ['png', 'pdf']
            #fig_fname = '{0}/{1}_{2}'.format(roc_dir, label, '_'.join(attack_labels_str))
            #fig = go.Figure(data=traces, layout=layout)
            #for ftype in ftypes:
            #    pio.write_image(fig, '{0}.{1}'.format(fig_fname, ftype))