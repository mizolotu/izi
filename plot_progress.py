import os
import os.path as osp
import argparse as arp
import pandas as pd
import numpy as np
import plotly.io as pio
import plotly.graph_objs as go

from common.plot import generate_line_scatter, moving_average, plot_and_save
from config import *

if __name__ == '__main__':

    # params

    parser = arp.ArgumentParser(description='Plot progress')
    parser.add_argument('-e', '--environment', help='Environment', default='ReactiveDiscreteEnv')
    parser.add_argument('-a', '--algorithms', help='Algorithms', nargs='+', default=['Baseline', 'ACER', 'ACKTR', 'PPO2'])
    #parser.add_argument('-s', '--scenario', help='Scenario name', default='anomaly_detection')
    #parser.add_argument('-l', '--labels', help='Attack labels', nargs='+', default=[2])
    parser.add_argument('-s', '--scenario', help='Scenario name', default='intrusion_detection')
    parser.add_argument('-l', '--labels', help='Attack labels', nargs='+', default=[1])
    parser.add_argument('-n', '--ntests', help='Number of tests', default=ntests, type=int)
    parser.add_argument('-t', '--timesteps', help='Total timesteps', type=int, default=int(2.5e5))
    args = parser.parse_args()

    # colors and labels

    names = [['Reward'], ['Benign traffic allowed'], ['Malicious traffic blocked'], ['Precision']]
    fnames = [f"{item}_{','.join([str(item) for item in args.labels])}" for item in ['reward', 'benign', 'malicious', 'precision']]
    ylabels = ['Reward value', 'Benign traffic allowed', 'Malicious traffic blocked', 'Precision']

    colors = ['goldenrod', 'royalblue', 'seagreen', 'firebrick']
    dashes = ['-', '--', ':', '-.']
    alg_names = ['Baseline', 'ACER', 'ACKTR', 'PPO']

    # algorithms and scenario

    env_fpath = osp.join(results_dir, args.environment)
    algorithms = [item for item in args.algorithms if item in os.listdir(env_fpath)]
    scenario = f"{args.scenario}_{','.join([str(item) for item in args.labels])}"

    # init data list

    data = [[], [], [], []]

    # loop through algorithms

    for algorithm in algorithms:

        # fpath

        algorithm_fpath = osp.join(env_fpath, algorithm)
        scenario_fpath = osp.join(algorithm_fpath, scenario)
        fname = osp.join(scenario_fpath, progress)

        # extract data

        p = pd.read_csv(fname, delimiter=',', dtype=float)
        r = p['ep_reward_mean'].values
        n = p['ep_normal_mean'].values
        a = p['ep_attack_mean'].values
        b = p['ep_precision_mean'].values
        tt = p['total_timesteps'].values

        dx = tt[0]

        nanidx = pd.isna(np.sum(p.values, axis=1))
        if 0:  # np.sum(nanidx) > 0:
            r = r[~nanidx]
            n = n[~nanidx]
            a = a[~nanidx]
            b = b[~nanidx]
            tt = tt[~nanidx]

        if len(tt) == len(np.unique(tt)):
            xmax = tt[-1]
        else:
            xmax = len(r) * dx

        print(algorithm, xmax, dx)

        if xmax == 0:
            s = args.timesteps // (nsteps * nenvs)
            x = np.arange(1, s + 1) * nsteps * nenvs
            r = np.ones(s) * np.nanmean(r)
            n = np.ones(s) * np.nanmean(n)
            a = np.ones(s) * np.nanmean(a)
            p = np.ones(s) * np.nanmean(p)
        else:
            dx_ = args.timesteps / xmax * dx
            print(algorithm, dx, dx_, len(r))
            x = np.arange(1, len(r) + 1) * dx_
            r = moving_average(r.reshape(len(r), 1)).reshape(x.shape)
            n = moving_average(n.reshape(len(n), 1)).reshape(x.shape)
            a = moving_average(a.reshape(len(a), 1)).reshape(x.shape)
            p = moving_average(b.reshape(len(a), 1)).reshape(x.shape)

        # append to lists

        data[0].append([x, r])
        data[1].append([x, n])
        data[2].append([x, a])
        data[3].append([x, p])

    # loop through data lists

    for d, f, y in zip(data, fnames, ylabels):
        # generate scatter

        fig_fname = '{0}/{1}'.format(progress_dir, f)
        plot_and_save(fig_fname, alg_names, d, colors, dashes, xlabel='Timesteps', ylabel=y, xrange=[0, args.timesteps], yrange=None)