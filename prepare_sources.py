import os, pandas, shutil
import argparse as arp
import os.path as osp
import tensorflow as tf
import numpy as np

from common.utils import download_controller

if __name__ == '__main__':

    # parse args

    parser = arp.ArgumentParser(description='Prepare sources')
    parser.add_argument('-i', '--input', help='Directory with trained models', default='models/classifiers')
    parser.add_argument('-o', '--output', help='Output directory name', default='sources/ids/')
    parser.add_argument('-f', '--fpr', help='FPR', default='0.01,0.0001,0.000001')
    args = parser.parse_args()

    # download controller

    download_controller(version='0.12.3')

    # input directories

    m_dir = osp.join(args.input, 'checkpoints')
    r_dir = osp.join(args.input, 'results')

    # output directories

    if not osp.isdir(args.output):
        os.mkdir(args.output)
    w_dir = osp.join(args.output, 'weights')
    if not osp.isdir(w_dir):
        os.mkdir(w_dir)
    t_dir = osp.join(args.output, 'thresholds')
    if not osp.isdir(t_dir):
        os.mkdir(t_dir)

    # compile models

    model_names = [item for item in os.listdir(m_dir) if osp.isdir(osp.join(m_dir, item))]
    for model_name in model_names:
        break
        spl = model_name.split('_')
        input_name = osp.join(m_dir, model_name)
        output_name = osp.join(w_dir, '{0}.tflite'.format('_'.join(spl[-2:])))
        converter = tf.lite.TFLiteConverter.from_saved_model(input_name)
        tflite_model = converter.convert()
        open(output_name, "wb").write(tflite_model)

    # select thresholds

    fpr_levels = [float(item) for item in args.fpr.split(',')]
    label_names = [item for item in os.listdir(r_dir) if osp.isdir(osp.join(r_dir, item))]
    for label_name in label_names:
        label_input = osp.join(r_dir, label_name)
        model_results = [osp.join(label_input, item) for item in os.listdir(label_input) if osp.isdir(osp.join(label_input, item))]
        for model_result in model_results:
            roc = pandas.read_csv(osp.join(model_result, 'roc.csv'), delimiter=' ', header=None).values
            thrs = []
            for fpr_level in fpr_levels:
                idx = np.where(roc[:, 0] <= fpr_level)[0][-1]
                thrs.append(str(roc[idx, 2]))
            spl = model_result.split('_')
            with open(osp.join(t_dir, '{0}.thr'.format('_'.join(spl[-2:]))), 'w') as f:
                f.write(','.join(thrs))

    # copy feature extraction functions

    if not osp.isdir('sources/ids/common'):
        os.mkdir('sources/ids/common')
    shutil.copy('common/pcap.py', 'sources/ids/common/')
    shutil.copy('common/data.py', 'sources/ids/common/')

    # copy meta

    shutil.copy('data/features/metainfo.json', 'sources/ids/')
