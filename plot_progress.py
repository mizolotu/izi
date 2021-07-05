import os
import os.path as osp
import argparse as arp
import pandas as pd
import numpy as np
import plotly.io as pio
import plotly.graph_objs as go

from common.plot import generate_line_scatter, moving_average
from config import *

if __name__ == '__main__':

    # params

    parser = arp.ArgumentParser(description='Plot progress')
    parser.add_argument('-e', '--environment', help='Environment', default='ReactiveDiscreteEnv')
    parser.add_argument('-a', '--algorithms', help='Algorithms', nargs='+', default=['PPO2'])
    parser.add_argument('-s', '--scenario', help='Scenario name', default='intrusion_detection')
    parser.add_argument('-l', '--labels', help='Attack labels', nargs='+', default=[1])
    parser.add_argument('-n', '--ntests', help='Number of tests', default=ntests, type=int)
    parser.add_argument('-t', '--timesteps', help='Total timesteps', type=int, default=int(3e5))
    args = parser.parse_args()

    # colors and labels

    names = [['Reward'], ['Benign traffic allowed, %'], ['Malicious traffic blocked, %'], ['Precision']]
    fnames = [f"{item}_{','.join([str(item) for item in args.labels])}" for item in ['reward', 'benign', 'malicious', 'precision']]
    ylabels = ['Reward value', 'Benign traffic allowed, %', 'Malicious traffic blocked, %', 'Precision']
    colors = ['rgb(64,120,211)', 'rgb(0,100,80)', 'rgb(237,2,11)', 'rgb(255,165,0)', 'rgb(139,0,139)', 'rgb(0,51,102)']

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
        x = p['total_timesteps'].values
        r = moving_average(r.reshape(len(r), 1)).reshape(x.shape)
        n = moving_average(n.reshape(len(n), 1)).reshape(x.shape) * 100
        a = moving_average(a.reshape(len(a), 1)).reshape(x.shape) * 100
        p = moving_average(b.reshape(len(a), 1)).reshape(x.shape)

        # baseline

        if len(r) <= args.ntests:
            x = np.arange(1, args.timesteps // nsteps) * x[0]
            r = np.ones(args.timesteps // nsteps) * np.nanmean(r)
            n = np.ones(args.timesteps // nsteps) * np.nanmean(n)
            a = np.ones(args.timesteps // nsteps) * np.nanmean(a)
            p = np.ones(args.timesteps // nsteps) * np.nanmean(p)

        # append to lists

        data[0].append([x, r])
        data[1].append([x, n])
        data[2].append([x, a])
        data[3].append([x, p])

    # loop through data lists

    for d, f, y in zip(data, fnames, ylabels):

        # generate scatter

        dashes = [None for _ in algorithms]
        traces, layout = generate_line_scatter(algorithms, d, colors, dashes, 'Time steps', y, show_legend=False, xrange=[0, args.timesteps])

        # save results

        ftypes = ['png', 'pdf']
        if not osp.exists(progress_dir):
            os.mkdir(progress_dir)
        fig_fname = '{0}/{1}'.format(progress_dir, f)
        fig = go.Figure(data=traces, layout=layout)
        for ftype in ftypes:
            pio.write_image(fig, '{0}.{1}'.format(fig_fname, ftype))