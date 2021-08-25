import os, sys
import os.path as osp
import argparse as arp
import numpy as np
import tensorflow as tf
import common.ml as models

from time import time
from sklearn.metrics import roc_curve
from sklearn.metrics import roc_auc_score
from common.ml import set_seeds, load_batches, classification_mapper, anomaly_detection_mapper, gan_mapper, load_meta, EarlyStoppingAtMaxMetric
from config import *

if __name__ == '__main__':

    parser = arp.ArgumentParser(description='Train classifiers')
    parser.add_argument('-m', '--model', help='Model', default='cnn', choices=['mlp', 'cnn', 'att', 'aen', 'som', 'bgn'])
    parser.add_argument('-l', '--layers', help='Number of layers', type=int, nargs='+')
    parser.add_argument('-e', '--earlystopping', help='Early stopping metric', default='acc', choices=['auc', 'acc'])
    parser.add_argument('-t', '--trlabels', help='Train labels', nargs='+', default=['0,1,2,3'])
    parser.add_argument('-v', '--vallabels', help='Validate labels', nargs='+', default=['0,1,2,3'])
    parser.add_argument('-i', '--inflabels', help='Inference labels', nargs='+', default=['0,1,2,3'])
    parser.add_argument('-s', '--steps', help='Polling step value or distribution', nargs='+', default=['0.0-1.0-0.001-3.0'])
    parser.add_argument('-c', '--cuda', help='Use CUDA', default=False, type=bool)

    args = parser.parse_args()

    if not args.cuda:
        os.environ["CUDA_VISIBLE_DEVICES"] = "-1"

    # global params

    num_batches = {
        'train': None,
        'validate': steps_per_epoch,
        'inference': steps_per_epoch,
    }

    num_epochs = {
        'train': None,
        'validate': 1,
        'inference': 1
    }

    # set seed for results reproduction

    if seed is not None:
        set_seeds(seed)

    # meta and labels

    meta = load_meta(data_dir)
    labels = sorted(meta['labels'])

    if args.trlabels is None:
        trlabels = labels
    else:
        trlabels = args.trlabels

    if args.vallabels is None:
        vallabels = trlabels
    else:
        vallabels = args.vallabels

    if args.inflabels is None:
        inflabels = trlabels
    else:
        inflabels = args.inflabels

    assert len(trlabels) == len(inflabels), 'List of train labels should have the same length as the list of test labels'
    assert len(trlabels) == len(vallabels), 'List of train labels should have the same length as the list of validation labels'

    for tr, val, inf in zip(trlabels, vallabels, inflabels):

        labels = {}

        if ',' in tr:
            trs = [int(item) for item in tr.split(',')]
        else:
            trs = [int(tr)]
        labels[stages[0]] = sorted(trs)
        train_labels_str = ','.join([str(item) for item in labels[stages[0]]])

        if ',' in val:
            val = [int(item) for item in val.split(',')]
        else:
            val = [int(val)]
        labels[stages[1]] = sorted(val)
        val_labels_str = ','.join([str(item) for item in labels[stages[1]]])

        if ',' in inf:
            infs = [int(item) for item in inf.split(',')]
        else:
            infs = [int(inf)]
        labels[stages[2]] = sorted(infs)
        inf_labels_str = ','.join([str(item) for item in labels[stages[2]]])

        print(f'Training using labels: {labels[stages[0]]}, validating using labels: {labels[stages[1]]}')

        # fpath

        fpaths = {}
        for stage in stages:
            fpaths[stage] = [osp.join(features_dir, str(int(label))) for label in labels[stage]]

        # create output directories

        if not osp.isdir(ids_models_dir):
            os.mkdir(ids_models_dir)
        if not osp.isdir(ids_results_dir):
            os.mkdir(ids_results_dir)

        foutput = osp.join(ids_results_dir, inf_labels_str)
        if not osp.isdir(foutput):
            os.mkdir(foutput)

        for step in args.steps:

            # input fpath

            fpaths_star = {}
            for stage in stages:
                fpaths_star[stage] = [osp.join(fpath, '*_{0}_{1}'.format(step, stage)) for fpath in fpaths[stage]]

            # meta

            nwindows = meta['nwindows']
            nfeatures = meta['nfeatures']
            xmin = np.array(meta['xmin'])
            xmax = np.array(meta['xmax'])

            # define model

            if args.cuda:
                strategy = tf.distribute.MirroredStrategy()
            else:
                strategy = tf.distribute.get_strategy()
            with strategy.scope():
                model_type = getattr(models, args.model)
                model_args = [nwindows, nfeatures]
                if args.layers is not None:
                    model_args.append(args.layers)
                model, model_name, detection_type = model_type(*model_args)
            model.summary()

            # mappers

            if detection_type == 'cl':
                mapper = lambda x, y: classification_mapper(x, y, nsteps=nwindows, nfeatures=nfeatures, xmin=xmin, xmax=xmax)
            elif detection_type == 'ad':
                if args.model in ['aen', 'som']:
                    mapper = lambda x, y: anomaly_detection_mapper(x, y, nsteps=nwindows, nfeatures=nfeatures, xmin=xmin, xmax=xmax)
                elif args.model in ['bgn']:
                    mapper = lambda x, y: gan_mapper(x, y, nsteps=nwindows, nfeatures=nfeatures, xmin=xmin, xmax=xmax)
            else:
                print('Unknown detection type!')
                sys.exit(1)

            # batches

            batches = {}
            for stage in stages:
                if 0 in labels[stage]:
                    if len(labels[stage]) > 1:
                        batch_shares = [0.5] + [0.5 / (len(labels[stage]) - 1) for _ in labels[stage][1:]]
                    else:
                        batch_shares = [1.0]
                else:
                    batch_shares = [1.0 / len(labels[stage]) for _ in labels[stage]]

                batches_ = [load_batches(fp, batch_size, nfeatures=nwindows*nfeatures+1).map(mapper) for fp in fpaths_star[stage]]
                batches[stage] = tf.data.experimental.sample_from_datasets(batches_, batch_shares).unbatch().shuffle(batch_size).batch(batch_size)
                if num_batches[stage] is not None:
                    batches[stage] = batches[stage].take(num_batches[stage])

            # create model and results directories

            m_path = osp.join(ids_models_dir, '{0}_{1}_{2}'.format(model_name, train_labels_str, step))
            if not osp.isdir(m_path):
                os.mkdir(m_path)

            # try to load the model

            try:
                model = tf.keras.models.load_model(m_path, compile=False)
                print(f'Model {model_name} has been loaded from {m_path}')

            # otherwise train a new one

            except Exception as e:
                print(e)
                print('Training model {0}'.format(model_name))

                if detection_type == 'cl':
                    cb = tf.keras.callbacks.EarlyStopping(monitor=f'val_{args.earlystopping}', verbose=0, patience=patience, mode='max', restore_best_weights=True)
                elif detection_type == 'ad':
                    cb = EarlyStoppingAtMaxMetric(validation_data=batches['validate'], metric=args.earlystopping, model_type=args.model)

                model.fit(
                    batches['train'],
                    validation_data=batches['validate'],
                    epochs=epochs,
                    steps_per_epoch=steps_per_epoch,
                    callbacks=[cb]
                )

                # save model

                model.save(m_path)

            # try to load thresholds

            thr_fpath = osp.join(m_path, 'thr')

            try:
                with open(thr_fpath, 'r') as f:
                    thrs = f.read()
                    thrs = thrs.split(',')
                    thrs = [float(thr) for thr in thrs]
                    assert len(thrs) == len(fpr_levels)
                    print(f'Found thresholds in {thr_fpath}')

            # otherwise calculate new ones

            except:

                print('Calculating new thresholds:')
                probs = []
                testy = []
                thrs = []
                for x, y in batches['validate']:
                    predictions = model.predict(x)
                    if detection_type == 'cl':
                        new_probs = predictions[:, 0]
                    elif detection_type == 'ad':
                        if args.model == 'aen':
                            new_probs = np.linalg.norm(predictions - y[:, :-1], axis=1)
                        elif args.model == 'som':
                            new_probs = predictions
                        y = y[:, -1]
                    probs = np.hstack([probs, new_probs])
                    testy = np.concatenate([testy, y])
                ns_fpr, ns_tpr, ns_thr = roc_curve(testy, probs)
                for fpr_level in fpr_levels:
                    idx = np.where(ns_fpr <= fpr_level)[0][-1]
                    thrs.append(str(ns_thr[idx]))
                    print(ns_fpr[idx], ns_tpr[idx], ns_thr[idx])

                # save thresholds

                open(osp.join(m_path, 'thr'), 'w').write(','.join(thrs))

            # test and calculate inference statistics

            print(f'Inferencing using labels: {labels[stages[2]]}')

            t_test = 0
            probs = []
            testy = []
            for x, y in batches['inference']:
                t_now = time()
                predictions = model.predict(x)
                if detection_type == 'cl':
                    new_probs = predictions[:, 0]
                elif detection_type == 'ad':
                    if args.model == 'aen':
                        new_probs = np.linalg.norm(predictions - y[:, :-1], axis=1)
                    elif args.model == 'som':
                        new_probs = predictions
                    y = y[:, -1]
                probs = np.hstack([probs, new_probs])
                testy = np.hstack([testy, y])
                t_test += (time() - t_now)

            sk_auc = roc_auc_score(testy, probs)
            ns_fpr, ns_tpr, ns_thr = roc_curve(testy, probs)
            roc = np.zeros((ns_fpr.shape[0], 3))
            roc[:, 0] = ns_fpr
            roc[:, 1] = ns_tpr
            roc[:, 2] = ns_thr

            # save the results

            results = [str(sk_auc)]

            r_path = osp.join(foutput, '{0}_{1}_{2}'.format(model_name, inf_labels_str, step))
            if not osp.isdir(r_path):
                os.mkdir(r_path)
            stats_path = osp.join(r_path, 'stats.csv')
            roc_path = osp.join(r_path, 'roc.csv')
            with open(stats_path, 'w') as f:
                f.write(','.join(results))
            np.savetxt(roc_path, roc)

