import os, pandas
import os.path as osp
import argparse as arp
import plotly.io as pio
import plotly.graph_objs as go

from common.plot import generate_line_scatter, moving_average
from config import *

if __name__ == '__main__':

    # params

    parser = arp.ArgumentParser(description='Plot progress')
    parser.add_argument('-i', '--input', help='Input directory', default='results/AttackMitigationEnv/PPO2')
    args = parser.parse_args()

    colors = [['rgb(64,120,211)'], ['rgb(0,100,80)'], ['rgb(237,2,11)'], ['rgb(255,165,0)', 'rgb(139,0,139)', 'rgb(0,51,102)']]

    fname = osp.join(args.input, 'progress.csv')
    p = pandas.read_csv(fname, delimiter=',', dtype=float)
    r = p['ep_reward_mean'].values
    n = p['ep_normal_mean'].values
    a = p['ep_attack_mean'].values
    b = p['ep_bonus_mean'].values
    x = p['total_timesteps'].values
    r = moving_average(r.reshape(len(r), 1)).reshape(x.shape)
    n = moving_average(n.reshape(len(n), 1)).reshape(x.shape) * 100
    a = moving_average(a.reshape(len(a), 1)).reshape(x.shape) * 100
    p = moving_average(b.reshape(len(a), 1)).reshape(x.shape) + 0.5

    data = [[[x, r]], [[x, n]], [[x, a]], [[x, p]]]
    names = [['Reward'], ['Benign traffic allowed, %'], ['Malicious traffic blocked, %'], ['Precision']]
    fnames = ['reward', 'benign', 'malicious', 'precision']
    ylabels = ['Reward value', 'Benign traffic allowed, %', 'Malicious traffic blocked, %', 'Precision']

    for d, n, f, y, c in zip(data, names, fnames, ylabels, colors):

        # generate scatter

        traces, layout = generate_line_scatter(n, d, c, 'Time steps', y, show_legend=True, xrange=[0, 1004800])

        # save results

        ftypes = ['png', 'pdf']
        if not osp.exists(progress_dir):
            os.mkdir(progress_dir)
        fig_fname = '{0}/{1}'.format(progress_dir, f)
        fig = go.Figure(data=traces, layout=layout)
        for ftype in ftypes:
            pio.write_image(fig, '{0}.{1}'.format(fig_fname, ftype))