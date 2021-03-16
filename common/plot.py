import plotly.graph_objs as go
import numpy as np

def moving_average(x, step=1, window=10):

    seq = []
    n = x.shape[0]

    for i in np.arange(0, n, step):
        idx = np.arange(np.maximum(0, i - window), np.minimum(n - 1, i + window + 1))
        seq.append(np.mean(x[idx, :], axis=0))

    return np.vstack(seq)

def generate_line_scatter(names, values, colors, xlabel, ylabel, xrange, show_legend=True):

    traces = []

    for i in range(len(names)):
        x = values[i][0].tolist()
        y = values[i][1].tolist()

        traces.append(
            go.Scatter(
                x=x,
                y=y,
                line=dict(color=colors[i]),
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
            zeroline=False
        ),
    )

    return traces, layout