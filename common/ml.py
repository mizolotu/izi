import json
import os.path as osp
import tensorflow as tf
import numpy as np

def load_batches(path, batch_size, nfeatures):
    batches = tf.data.experimental.make_csv_dataset(
        path,
        batch_size=batch_size,
        header=False,
        shuffle=True,
        column_names=[str(i) for i in range(nfeatures)],
        column_defaults=[tf.float32 for _ in range(nfeatures)],
        select_columns=[str(i) for i in range(nfeatures)],
        label_name='{0}'.format(nfeatures - 1),
    )
    return batches

def load_meta(fpath, fname='metainfo.json'):
    meta = None
    try:
        with open(osp.join(fpath, fname)) as f:
            meta = json.load(f)
    except Exception as e:
        print(e)
    return meta

def set_seeds(seed):
    tf.random.set_seed(seed)
    np.random.seed(seed)

def classification_mapper(features, label, xmin, xmax, eps=1e-10):
    features = (tf.stack(list(features.values()), axis=-1) - xmin) / (xmax - xmin + eps)
    label = tf.clip_by_value(label, 0, 1)
    return features, label

def mlp(nfeatures, nl, nh, dropout=0.5, batchnorm=True, lr=5e-5):
    inputs = tf.keras.layers.Input(shape=(nfeatures - 1,))
    if batchnorm:
        hidden = tf.keras.layers.BatchNormalization()(inputs)
    else:
        hidden = inputs
    for _ in range(nl):
        hidden = tf.keras.layers.Dense(nh, activation='relu')(hidden)
        if dropout is not None:
            hidden = tf.keras.layers.Dropout(dropout)(hidden)
    outputs = tf.keras.layers.Dense(1, activation='sigmoid')(hidden)
    model = tf.keras.models.Model(inputs=inputs, outputs=outputs)
    model.compile(loss=tf.keras.losses.BinaryCrossentropy(), optimizer=tf.keras.optimizers.Adam(lr=lr), metrics=[tf.keras.metrics.AUC(name='auc'), 'binary_accuracy'])
    return model, 'mlp_{0}_{1}'.format(nh, nl)

def identity_block(x, nhidden):  # h = f(x) + x
    h = tf.keras.layers.Dense(nhidden)(x)
    h = tf.keras.layers.BatchNormalization()(h)
    h = tf.keras.layers.Add()([x, h])
    h = tf.keras.layers.Activation(activation='relu')(h)
    return h

def dense_block(x, nhidden):  # h = f(x) + g(x)
    h = tf.keras.layers.Dense(nhidden)(x)
    h = tf.keras.layers.BatchNormalization()(h)
    s = tf.keras.layers.Dense(nhidden)(x)
    s = tf.keras.layers.BatchNormalization()(s)
    h = tf.keras.layers.Add()([s, h])
    h = tf.keras.layers.Activation(activation='relu')(h)
    return h

def res(nfeatures, nb, nh, dropout=0.5, lr=5e-5):
    inputs = tf.keras.layers.Input(shape=(nfeatures - 1,))
    hidden = tf.keras.layers.Dense(nh)(inputs)
    for _ in range(nb):
        hidden = identity_block(hidden, nh)
        hidden = dense_block(hidden, nh)
        if dropout is not None:
            hidden = tf.keras.layers.Dropout(dropout)(hidden)
    outputs = tf.keras.layers.Dense(1, activation='sigmoid')(hidden)
    model = tf.keras.models.Model(inputs=inputs, outputs=outputs)
    model.compile(loss=tf.keras.losses.BinaryCrossentropy(), optimizer=tf.keras.optimizers.Adam(lr=lr), metrics=[tf.keras.metrics.AUC(name='auc'), 'binary_accuracy'])
    return model, 'resnet_{0}_{1}'.format(nb, nh)

def attention_block(x, nh):
    q = tf.keras.layers.Dense(nh, use_bias=False)(x)
    k = tf.keras.layers.Dense(nh, use_bias=False)(x)
    v = tf.keras.layers.Dense(nh, use_bias=False)(x)
    a = tf.keras.layers.Multiply()([q, k])
    a = tf.keras.layers.Softmax(axis=-1)(a)
    h = tf.keras.layers.Multiply()([a, v])
    return h

def att(nfeatures, nb, nh, dropout=0.5, batchnorm=True, lr=5e-5):
    inputs = tf.keras.layers.Input(shape=(nfeatures - 1,))
    if batchnorm:
        hidden = tf.keras.layers.BatchNormalization()(inputs)
    else:
        hidden = inputs
    for _ in range(nb):
        hidden = attention_block(hidden, nh)
        if dropout is not None:
            hidden = tf.keras.layers.Dropout(dropout)(hidden)
    outputs = tf.keras.layers.Dense(1, activation='sigmoid')(hidden)
    model = tf.keras.models.Model(inputs=inputs, outputs=outputs)
    model.compile(loss=tf.keras.losses.BinaryCrossentropy(), optimizer=tf.keras.optimizers.Adam(lr=lr), metrics=[tf.keras.metrics.AUC(name='auc'), 'binary_accuracy'])
    return model, 'attnet_{0}_{1}'.format(nb, nh)