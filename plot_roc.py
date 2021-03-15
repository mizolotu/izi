import os
import os.path as osp
import plotly.io as pio
import plotly.graph_objs as go
import numpy as np

from common.plot import generate_line_scatter
from config import *

if __name__ == '__main__':

    colors = ['rgb(237,2,11)', 'rgb(255,165,0)', 'rgb(139,0,139)', 'rgb(0,51,102)', 'rgb(255,0,255)', 'rgb(210,105,30)', 'rgb(0,255,0)', 'rgb(0,0,128)']

    for label in os.listdir(classfier_results_dir):

        # prepare data

        data = []
        names = []
        models_path = osp.join(classfier_results_dir, label)
        models = os.listdir(models_path)
        model_names = []
        for m in models:
            spl = m.split('_')
            w = spl[-2]
            if spl[-1] == '0':
                m_type = 'general'
            else:
                m_type = 'special'
            model_names.append('{0}, {1} sec.'.format(m_type, w))
        m_idx = sorted(range(len(model_names)), key=lambda k: model_names[k])

        for idx in m_idx:
            model_path = osp.join(models_path, models[idx])
            if osp.isdir(model_path) and roc_fname in os.listdir(model_path):
                roc_path = osp.join(model_path, roc_fname)
                roc = np.genfromtxt(roc_path, dtype=float, delimiter=' ')
                model_name = '-'.join(models[idx].split('_'))
                x = roc[:, 0]
                y = roc[:, 1]
                data.append([x, y])
                names.append(model_names[idx])

        # generate layout and traces

        traces, layout = generate_line_scatter(names, data, colors, xlabel='FPR', ylabel='TPR', xrange=[0, 1], yrange=[0, 1])

        # save results

        ftypes = ['png', 'pdf']
        fig_fname = '{0}/{1}'.format(roc_dir, label)
        fig = go.Figure(data=traces, layout=layout)
        for ftype in ftypes:
            pio.write_image(fig, '{0}.{1}'.format(fig_fname, ftype))
