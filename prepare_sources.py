import os
import argparse as arp
import os.path as osp
import tensorflow as tf

from common.odl import download_controller

if __name__ == '__main__':

    # parse args

    parser = arp.ArgumentParser(description='Prepare sources')
    parser.add_argument('-i', '--input', help='Directory with trained models', default='models/classifiers')
    parser.add_argument('-o', '--output', help='Output directory name', default='sources/ids/models')
    args = parser.parse_args()

    # download controller

    download_controller(version='0.12.3')

    # compile models

    if not osp.isdir(args.output):
        os.mkdir(args.output)
    m_dir = osp.join(args.input, 'checkpoints')
    r_dir = osp.join(args.input, 'results')
    model_names = [item for item in os.listdir(m_dir) if osp.isdir(osp.join(m_dir, item))]
    for model_name in model_names:
        spl = model_name.split('_')
        input_name = osp.join(m_dir, model_name)
        output_name = osp.join(args.output, '{0}.tflite'.format('_'.join(spl[-2:])))
        converter = tf.lite.TFLiteConverter.from_saved_model(input_name)
        tflite_model = converter.convert()
        open(output_name, "wb").write(tflite_model)

    # select thresholds

    label_names = [item for item in os.listdir(r_dir) if osp.isdir(osp.join(r_dir, item))]
    for label_name in label_names:
        label_input = osp.join(r_dir, label_name)
        model_results = [item for item in os.listdir(label_input) if osp.isdir(osp.join(label_input, item))]



        # shutil.copytree(osp.join(best_model_input, 'classifier'), label_output, dirs_exist_ok=True)

        roc = pandas.read_csv(osp.join(best_model_result, 'roc.csv'), delimiter=' ', header=None).values
        thrs = []
        for fpr_level in fpr_levels:
            idx = np.where(roc[:, 0] <= fpr_level)[0][-1]
            thrs.append(str(roc[idx, 2]))
        with open(osp.join(output_dir, '{0}.thr'.format(label_name)), 'w') as f:
            f.write(','.join(thrs))