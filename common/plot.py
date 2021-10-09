import plotly.graph_objs as go
import numpy as np
from matplotlib import pyplot as pp

def moving_average(x, step=1, window=25):

    seq = []
    n = x.shape[0]

    for i in np.arange(0, n, step):
        idx = np.arange(np.maximum(0, i - window), np.minimum(n - 1, i + window + 1))
        seq.append(np.nanmean(x[idx, :], axis=0))

    return np.vstack(seq)

def plot_and_save(fpath, names, data, colors, linestyles, xlabel, ylabel, xrange, yrange):
    pp.figure(figsize=(10, 8))
    for n, d, c, l in zip(names, data, colors, linestyles):
        x, y = d
        pp.plot(x, y, linestyle=l, color=c, linewidth=2, label=n)
    pp.xlim(xrange)
    pp.ylim(yrange)
    pp.xlabel(xlabel, fontdict={'size': 12})
    pp.ylabel(ylabel, fontdict={'size': 12})
    pp.xticks(fontsize=12)
    pp.yticks(fontsize=12)
    pp.legend()
    pp.savefig(f'{fpath}.pdf', bbox_inches='tight')
    pp.savefig(f'{fpath}.png', bbox_inches='tight')
    pp.close()

def generate_line_scatter(names, values, colors, dashes, xlabel, ylabel, xrange, yrange, show_legend=True, yanchor='bottom', xlegend=1, ylegend=0):

    traces = []

    for i in range(len(names)):

        x = values[i][0].tolist()
        y = values[i][1].tolist()

        traces.append(
            go.Scatter(
                x=x,
                y=y,
                line=dict(color=colors[i], dash=dashes[i]),
                mode='lines',
                showlegend=show_legend,
                name=names[i],
            )
        )

    layout = go.Layout(
        template='plotly_white',
        xaxis=dict(
            title=xlabel,
            showgrid=True,
            showline=False,
            showticklabels=True,
            ticks='outside',
            zeroline=False,
            range=xrange
        ),
        yaxis=dict(
            title=ylabel,
            showgrid=True,
            showline=False,
            showticklabels=True,
            ticks='outside',
            zeroline=False,
            range=yrange
        ),
        legend=dict(
            yanchor=yanchor,
            y=ylegend,
            xanchor="right",
            x=1
        )
    )

    return traces, layout

def generate_marker_scatter(names, values, colors, markers, xlabel, ylabel, xrange, show_legend=True):

    traces = []

    for i in range(len(names)):

        x = values[i][0].tolist()
        y = values[i][1].tolist()

        traces.append(
            go.Scatter(
                x=x,
                y=y,
                line=dict(color=colors[i]),
                mode='lines+markers',
                showlegend=show_legend,
                name=names[i],
                marker=dict(symbol=markers[i])
            )
        )

    layout = go.Layout(
        template='plotly_white',
        xaxis=dict(
            title=xlabel,
            showgrid=True,
            showline=False,
            showticklabels=True,
            ticks='outside',
            zeroline=False,
            range=xrange
        ),
        yaxis=dict(
            title=ylabel,
            showgrid=True,
            showline=False,
            showticklabels=True,
            ticks='outside',
            zeroline=False
        ),
    )

    return traces, layout