import os, pandas
import os.path as osp
import argparse as arp
import plotly.io as pio
import plotly.graph_objs as go

from common.plot import generate_line_scatter, moving_average

if __name__ == '__main__':

    # args

    parser = arp.ArgumentParser(description='Plot results of using state-of-art RL alghorithms in OpenAI gym')
    parser.add_argument('-i', '--input', help='Input directory', default='results/AttackMitigationEnv/PPO2/MlpPolicy/part2')
    parser.add_argument('-o', '--output', help='Output directory', default='figures')
    args = parser.parse_args()

    scenario_name = 'scenario{0}'.format(args.input.split('/')[-1])

    #colors = ['rgb(64,120,211)', 'rgb(0,100,80)', 'rgb(237,2,11)', 'rgb(255,165,0)', 'rgb(139,0,139)', 'rgb(0,51,102)']

    colors = [['rgb(64,120,211)'], ['rgb(237,2,11)']]

    fname = osp.join(args.input, 'progress.csv')
    p = pandas.read_csv(fname, delimiter=',', dtype=float)
    y = p['ep_reward_mean'].values
    n = p['ep_normal_mean'].values
    a = p['ep_attack_mean'].values
    x = p['total_timesteps'].values
    y = moving_average(y.reshape(len(y), 1)).reshape(x.shape)
    n = moving_average(n.reshape(len(n), 1)).reshape(x.shape)
    a = moving_average(a.reshape(len(a), 1)).reshape(x.shape)

    data = [[[x, y]], [[x, a]]]
    names = [['Reward'], ['Malicious traffic']]
    fnames = ['reward', 'traffic']
    ylabels = ['Reward value', 'Malicious traffic']

    for d, n, c, f, y in zip(data, names, colors, fnames, ylabels):
        traces, layout = generate_line_scatter(n, d, c, 'Time steps', y, show_legend=False)

        # save results

        ftypes = ['png', 'pdf']
        if not osp.exists(args.output):
            os.mkdir(args.output)
        fig_fname = '{0}/{1}'.format(args.output, f)
        fig = go.Figure(data=traces, layout=layout)
        for ftype in ftypes:
            pio.write_image(fig, '{0}.{1}'.format(fig_fname, ftype))