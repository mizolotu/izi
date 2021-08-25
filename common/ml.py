import json
import os.path as osp
import tensorflow as tf
import numpy as np

from sklearn.metrics import roc_auc_score
from config import gan_latent_dim

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

def classification_mapper(features, label, nsteps, nfeatures, xmin, xmax, eps=1e-10):
    features = tf.stack(list(features.values()), axis=-1)
    features = tf.reshape(features, [-1, nsteps, nfeatures])
    features = (features - xmin[None, None, :]) / (xmax[None, None, :] - xmin[None, None, :] + eps)
    label = tf.clip_by_value(label, 0, 1)
    return features, label

def anomaly_detection_mapper(features, label, nsteps, nfeatures, xmin, xmax, eps=1e-10):
    features = tf.stack(list(features.values()), axis=-1)
    features = tf.reshape(features, [-1, nsteps, nfeatures])
    features = (features - xmin[None, None, :]) / (xmax[None, None, :] - xmin[None, None, :] + eps)
    label = tf.clip_by_value(label, 0, 1)
    features_with_labels = tf.reshape(features, [-1, nsteps * nfeatures])
    features_with_labels = tf.concat([features_with_labels, tf.reshape(label, (-1, 1))], axis=1)
    return features, features_with_labels

def gan_mapper(features, label, nsteps, nfeatures, xmin, xmax, latent_dim=gan_latent_dim, eps=1e-10):
    features = tf.stack(list(features.values()), axis=-1)
    features = tf.reshape(features, [-1, nsteps, nfeatures])
    features = (features - xmin[None, None, :]) / (xmax[None, None, :] - xmin[None, None, :] + eps)
    label = tf.clip_by_value(label, 0, 1)
    z = tf.random.uniform(shape=(features.shape[0], tf.constant(latent_dim)))
    z_with_labels = tf.concat([z, tf.reshape(label, (-1, 1))], axis=1)
    return features, z_with_labels

def mlp(nsteps, nfeatures, layers=[768, 768], nhidden=512, batchnorm=True, dropout=0.5, lr=5e-5):
    inputs = tf.keras.layers.Input(shape=(nsteps, nfeatures,))
    if batchnorm:
        hidden = tf.keras.layers.BatchNormalization()(inputs)
    else:
        hidden = inputs
    hidden = tf.keras.layers.Flatten()(hidden)
    for layer in layers:
        hidden = tf.keras.layers.Dense(layer, activation='relu')(hidden)
        if dropout is not None:
            hidden = tf.keras.layers.Dropout(dropout)(hidden)
    hidden = tf.keras.layers.Dense(nhidden, activation='relu')(hidden)
    outputs = tf.keras.layers.Dense(1, activation='sigmoid')(hidden)
    model = tf.keras.models.Model(inputs=inputs, outputs=outputs)
    model.compile(loss=tf.keras.losses.BinaryCrossentropy(), optimizer=tf.keras.optimizers.Adam(lr=lr), metrics=[tf.keras.metrics.AUC(name='auc'), tf.keras.metrics.BinaryAccuracy(name='acc'), tf.keras.metrics.Precision(name='pre')])
    return model, 'mlp_{0}'.format('-'.join([str(item) for item in layers])), 'cl'

def cnn(nsteps, nfeatures, layers=[512, 512], kernel_size=2, nhidden=512, batchnorm=True, dropout=0.5, lr=5e-5):
    inputs = tf.keras.layers.Input(shape=(nsteps, nfeatures,))
    if batchnorm:
        hidden = tf.keras.layers.BatchNormalization()(inputs)
    else:
        hidden = inputs
    for nfilters in layers:
        hidden = tf.keras.layers.Conv1D(nfilters, kernel_size, activation='relu')(hidden)
        if dropout is not None:
            hidden = tf.keras.layers.Dropout(dropout)(hidden)
    hidden = tf.keras.layers.Flatten()(hidden)
    hidden = tf.keras.layers.Dense(nhidden, activation='relu')(hidden)
    outputs = tf.keras.layers.Dense(1, activation='sigmoid')(hidden)
    model = tf.keras.models.Model(inputs=inputs, outputs=outputs)
    model.compile(loss=tf.keras.losses.BinaryCrossentropy(), optimizer=tf.keras.optimizers.Adam(lr=lr), metrics=[tf.keras.metrics.AUC(name='auc'), tf.keras.metrics.BinaryAccuracy(name='acc'), tf.keras.metrics.Precision(name='pre')])
    return model, 'cnn_{0}'.format('-'.join([str(item) for item in layers])), 'cl'

def attention_block(x, nh):
    q = tf.keras.layers.Dense(nh, use_bias=False)(x)
    k = tf.keras.layers.Dense(nh, use_bias=False)(x)
    v = tf.keras.layers.Dense(nh, use_bias=False)(x)
    a = tf.keras.layers.Multiply()([q, k])
    a = tf.keras.layers.Softmax(axis=-1)(a)
    h = tf.keras.layers.Multiply()([a, v])
    return h

def att(nsteps, nfeatures, layers=[512], nhidden=512, batchnorm=True, dropout=0.5, lr=5e-5):
    inputs = tf.keras.layers.Input(shape=(nsteps, nfeatures,))
    if batchnorm:
        hidden = tf.keras.layers.BatchNormalization()(inputs)
    else:
        hidden = inputs
    for asize in layers:
        hidden = attention_block(hidden, asize)
        if dropout is not None:
            hidden = tf.keras.layers.Dropout(dropout)(hidden)
    hidden = tf.keras.layers.Flatten()(hidden)
    hidden = tf.keras.layers.Dense(nhidden, activation='relu')(hidden)
    outputs = tf.keras.layers.Dense(1, activation='sigmoid')(hidden)
    model = tf.keras.models.Model(inputs=inputs, outputs=outputs)
    model.compile(loss=tf.keras.losses.BinaryCrossentropy(), optimizer=tf.keras.optimizers.Adam(lr=lr), metrics=[tf.keras.metrics.AUC(name='auc'), tf.keras.metrics.BinaryAccuracy(name='acc'), tf.keras.metrics.Precision(name='pre')])
    return model, 'att_{0}'.format('-'.join([str(item) for item in layers])), 'cl'

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

def ae_reconstruction_loss(y_true, y_pred):
    y_true, _ = tf.split(y_true, [y_pred.shape[1] * y_pred.shape[2], 1], axis=1)
    y_true = tf.reshape(y_true, [-1, y_pred.shape[1], y_pred.shape[2]])
    squared_difference = tf.square(y_true - y_pred)
    return tf.reduce_mean(tf.math.sqrt(tf.reduce_sum(squared_difference, axis=-1)), axis=-1)

class ReconstructionAuc(tf.keras.metrics.Metric):

    def __init__(self, m, n, name='reconstruction_auc', **kwargs):
        super(ReconstructionAuc, self).__init__(name=name, **kwargs)
        self.auc = tf.keras.metrics.AUC()
        self.reconstruction_errors = tf.Variable([], shape=(None,), validate_shape=False)
        self.ta_index = tf.Variable([[0]])
        self.reconstruction_errors_per_batch = tf.Variable(shape=(m, n), validate_shape=False)
        self.true_labels = tf.Variable([], shape=(None,), validate_shape=False)
        self.update_metric = tf.Variable(False)

    def update_state(self, y_true, y_pred, sample_weight=None):
        if self.update_metric:
            y_true, label_true = tf.split(y_true, [y_pred.shape[1], 1], axis=1)
            label_true = tf.clip_by_value(label_true, 0, 1)
            reconstruction_errors = tf.math.sqrt(tf.reduce_sum(tf.square(y_true - y_pred), axis=-1))
            self.reconstruction_errors_per_batch = tf.tensor_scatter_nd_update(self.reconstruction_errors_per_batch.value(), self.ta_index, [reconstruction_errors])
            self.ta_index.assign([[1]])
            self.true_labels.assign(tf.concat([self.true_labels.value(), label_true[:, 0]], axis=0))

    def result(self):
        self.reconstruction_errors = tf.reshape(self.reconstruction_errors_per_batch, (self.reconstruction_errors_per_batch.shape[0] * self.reconstruction_errors_per_batch.shape[1],))
        probs = self.reconstruction_errors / tf.math.reduce_max(self.reconstruction_errors)
        self.auc.update_state(self.true_labels, probs)
        return self.auc.result()

    def reset_states(self):
        self.reconstruction_errors.assign([])
        self.true_labels.assign([])
        self.auc.reset_states()

class ToggleMetrics(tf.keras.callbacks.Callback):

    def on_test_begin(self, logs):
        for metric in self.model.metrics:
            if 'auc' in metric.name:
                metric.update_metric.assign(True)
    def on_test_end(self,  logs):
        for metric in self.model.metrics:
            if 'auc' in metric.name:
                metric.update_metric.assign(False)

class EarlyStoppingAtMaxMetric(tf.keras.callbacks.Callback):

    def __init__(self, validation_data, metric, patience=10, model_type='aen'):
        super(EarlyStoppingAtMaxMetric, self).__init__()
        self.patience = patience
        self.best_weights = None
        self.metric = metric
        self.validation_data = validation_data
        self.current = -np.Inf
        self.model_type = model_type

    def on_train_begin(self, logs=None):
        self.wait = 0
        self.stopped_epoch = 0
        self.best = -np.Inf

    def on_epoch_end(self, epoch, logs=None):
        if np.greater(self.current, self.best):
            self.best = self.current
            self.wait = 0
            self.best_weights = self.model.get_weights()
        else:
            self.wait += 1
            if self.wait >= self.patience:
                self.stopped_epoch = epoch
                self.model.stop_training = True
                self.model.set_weights(self.best_weights)

    def on_test_end(self, logs):
        probs = []
        testy = []
        for x, y in self.validation_data:
            y_labels = np.clip(y[:, -1], 0, 1)
            reconstructions = self.model.predict(x)
            if self.model_type == 'aen':
                new_probs = np.mean(np.linalg.norm(reconstructions - x, axis=-1), axis=-1)
            elif self.model_type == 'som':
                new_probs = reconstructions
            elif self.model_type == 'bgn':
                new_probs = reconstructions
            else:
                raise NotImplemented
            probs = np.hstack([probs, new_probs])
            testy = np.hstack([testy, y_labels])
        if self.metric == 'auc':
            self.current = roc_auc_score(testy, probs)
        elif self.metric == 'acc':
            n = len(testy)
            p0 = probs[np.where(testy == 0)[0]]
            p1 = probs[np.where(testy == 1)[0]]
            p0si = np.argsort(p0)
            p1si = np.argsort(p1)
            p0s = p0[p0si]
            p1s = p1[p1si]
            n0 = len(p0s)
            n1 = len(p1s)
            if p1s[0] > p0s[-1]:
                acc = [1]
            else:
                idx = np.where(p0s > p1s[0])[0]
                acc = [float(len(p0s) - len(idx) + len(p1s)) / n, *np.zeros(len(idx))]
                h = n0 - len(idx)
                n10 = 0
                for i, j in enumerate(idx):
                    thr = p0s[j]
                    thridx = np.where(p1s[n10:] < thr)[0]
                    n10 += len(thridx)
                    h += 1
                    acc[i + 1] = (h - n10 + n1) / n
            self.current = np.max(acc)
        else:
            raise NotImplemented
        print(f'\nValidation {self.metric}:', self.current)

class ReconstructionPrecision(tf.keras.metrics.Metric):

    def __init__(self, name='reconstruction_precision', alpha=3, **kwargs):
        super(ReconstructionPrecision, self).__init__(name=name, **kwargs)
        self.alpha = alpha
        self.reconstruction_errors = tf.Variable([], shape=(None,), validate_shape=False)
        self.true_labels = tf.Variable([], shape=(None,), validate_shape=False)

    def update_state(self, y_true, y_pred, sample_weight=None):
        y_true, label_true = tf.split(y_true, [y_pred.shape[1], 1], axis=1)
        label_true = tf.clip_by_value(label_true, 0, 1)
        reconstruction_errors = tf.math.sqrt(tf.reduce_sum(tf.square(y_true - y_pred), axis=-1))
        self.reconstruction_errors.assign(tf.concat([self.reconstruction_errors.value(), reconstruction_errors], axis=0))
        self.true_labels.assign(tf.concat([self.true_labels.value(), label_true[:, 0]], axis=0))

    def result(self):
        thr = tf.reduce_mean(self.reconstruction_errors) + self.alpha * tf.math.reduce_std(self.reconstruction_errors)
        predictions = tf.math.greater_equal(self.reconstruction_errors, thr)
        true_labels = tf.cast(self.true_labels, tf.bool)
        true_positives = tf.logical_and(tf.equal(predictions, True), tf.equal(true_labels, True))
        true_positives = tf.cast(true_positives, self.dtype)
        false_positives = tf.logical_and(tf.equal(predictions, True), tf.equal(true_labels, False))
        false_positives = tf.cast(false_positives, self.dtype)
        return tf.reduce_sum(true_positives)  / (tf.reduce_sum(true_positives) + tf.reduce_sum(false_positives))

    def reset_states(self):
        self.reconstruction_errors.assign([])
        self.true_labels.assign([])

class ReconstructionAccuracy(tf.keras.metrics.Metric):

    def __init__(self, name='reconstruction_accuracy', alpha=3, **kwargs):
        super(ReconstructionAccuracy, self).__init__(name=name, **kwargs)
        self.alpha = alpha
        self.reconstruction_errors = tf.Variable([], shape=(None,), validate_shape=False)
        self.true_labels = tf.Variable([], shape=(None,), validate_shape=False)

    def update_state(self, y_true, y_pred, sample_weight=None):
        y_true, label_true = tf.split(y_true, [y_pred.shape[1], 1], axis=1)
        label_true = tf.clip_by_value(label_true, 0, 1)
        reconstruction_errors = tf.math.sqrt(tf.reduce_sum(tf.square(y_true - y_pred), axis=-1))
        self.reconstruction_errors.assign(tf.concat([self.reconstruction_errors.value(), reconstruction_errors], axis=0))
        self.true_labels.assign(tf.concat([self.true_labels.value(), label_true[:, 0]], axis=0))

    def result(self):
        thr = tf.reduce_mean(self.reconstruction_errors) + self.alpha * tf.math.reduce_std(self.reconstruction_errors)
        predictions = tf.math.greater_equal(self.reconstruction_errors, thr)
        true_labels = tf.cast(self.true_labels, tf.bool)
        true_positives = tf.logical_and(tf.equal(predictions, True), tf.equal(true_labels, True))
        true_positives = tf.cast(true_positives, self.dtype)
        true_negatives = tf.logical_and(tf.equal(predictions, False), tf.equal(true_labels, False))
        true_negatives = tf.cast(true_negatives, self.dtype)
        false_positives = tf.logical_and(tf.equal(predictions, True), tf.equal(true_labels, False))
        false_positives = tf.cast(false_positives, self.dtype)
        false_negatives = tf.logical_and(tf.equal(predictions, False), tf.equal(true_labels, True))
        false_negatives = tf.cast(false_negatives, self.dtype)
        return (tf.reduce_sum(true_positives) + tf.reduce_sum(true_negatives))  / (tf.reduce_sum(true_positives) + tf.reduce_sum(true_negatives) + tf.reduce_sum(false_positives) + tf.reduce_sum(false_negatives))

    def reset_states(self):
        self.reconstruction_errors.assign([])
        self.true_labels.assign([])

def aen(nsteps, nfeatures, layers=[512, 512], kernel_size=2, nhidden=32, dropout=0.5, batchnorm=True, lr=5e-5):
    inputs = tf.keras.layers.Input(shape=(nsteps, nfeatures,))
    if batchnorm:
        hidden = tf.keras.layers.BatchNormalization()(inputs)
    else:
        hidden = inputs
    for nfilters in layers:
        hidden = tf.keras.layers.Conv1D(nfilters, kernel_size, activation='relu')(hidden)
        if dropout is not None:
            hidden = tf.keras.layers.Dropout(dropout)(hidden)
    hidden = tf.keras.layers.Dense(nhidden, activation='relu')(hidden)
    for nfilters in layers:
        hidden = tf.keras.layers.Conv1DTranspose(nfilters, kernel_size, activation='relu')(hidden)
        if dropout is not None:
            hidden = tf.keras.layers.Dropout(dropout)(hidden)
    outputs = tf.keras.layers.Dense(nfeatures, activation='sigmoid')(hidden)
    model = tf.keras.models.Model(inputs=inputs, outputs=outputs)
    model.compile(loss=ae_reconstruction_loss, optimizer=tf.keras.optimizers.Adam(lr=lr))
    return model, 'aen_{0}'.format('-'.join([str(item) for item in layers])), 'ad'

class Sampling(tf.keras.layers.Layer):

    def call(self, inputs):
        z_mean, z_log_var = inputs
        batch = tf.shape(z_mean)[0]
        dim = tf.shape(z_mean)[1]
        epsilon = tf.keras.backend.random_normal(shape=(batch, dim))
        return z_mean + tf.exp(0.5 * z_log_var) * epsilon

class Encoder(tf.keras.layers.Layer):

    def __init__(self, nfeatures, nl, nh, dropout, batchnorm, name='encoder', **kwargs):
        super(Encoder, self).__init__(name=name, **kwargs)
        self.layers = []
        if batchnorm:
            norm = tf.keras.layers.BatchNormalization()
            self.layers.append(norm)
        for i in range(nl):
            self.layers.append(tf.keras.layers.Dense(nh, activation='relu'))
            if dropout is not None:
                self.layers.append(tf.keras.layers.Dropout(dropout))
        self.dense_mean = tf.keras.layers.Dense(nfeatures - 1)
        self.dense_log_var = tf.keras.layers.Dense(nfeatures - 1)
        self.sampling = Sampling()

    def call(self, inputs):
        x = inputs
        for layer in self.layers:
            x = layer(x)
        z_mean = self.dense_mean(x)
        z_log_var = self.dense_log_var(x)
        z = self.sampling((z_mean, z_log_var))
        return z_mean, z_log_var, z

class Decoder(tf.keras.layers.Layer):

    def __init__(self, nfeatures, nl, nh, dropout, name='decoder', **kwargs):
        super(Decoder, self).__init__(name=name, **kwargs)
        self.layers = []
        for i in range(nl):
            self.layers.append(tf.keras.layers.Dense(nh, activation='relu'))
            if dropout is not None:
                self.layers.append(tf.keras.layers.Dropout(dropout))
        self.dense_output = tf.keras.layers.Dense(nfeatures - 1, activation='sigmoid')

    def call(self, inputs):
        x = inputs
        for layer in self.layers:
            x = layer(x)
        return self.dense_output(x)

class VariationalAutoEncoder(tf.keras.Model):

    def __init__(self, nfeatures,  nl, nh, dropout, batchnorm, name='autoencoder', **kwargs):
        super(VariationalAutoEncoder, self).__init__(name=name, **kwargs)
        self.encoder = Encoder(nfeatures, nl, nh, dropout, batchnorm)
        self.decoder = Decoder(nfeatures, nl, nh, dropout)
        self.total_loss_tracker = tf.keras.metrics.Mean(name='total_loss')
        self.precision = ReconstructionPrecision(name='pre')
        self.accuracy = ReconstructionAccuracy(name='acc')

    def call(self, inputs):
        z_mean, z_log_var, z = self.encoder(inputs)
        reconstruction = self.decoder(z)
        return reconstruction

    @property
    def metrics(self):
        return [
            self.total_loss_tracker,
            self.precision,
            self.accuracy
        ]

    def train_step(self, data):
        inputs, outputs = data
        with tf.GradientTape() as tape:
            z_mean, z_log_var, z = self.encoder(inputs)
            reconstruction = self.decoder(z)
            y_true, _ = tf.split(outputs, [reconstruction.shape[1], 1], axis=-1)
            reconstruction_loss = tf.math.sqrt(tf.reduce_sum(tf.square(y_true - reconstruction), axis=-1))
            kl_loss = - 0.5 * (1 + z_log_var - tf.square(z_mean) - tf.exp(z_log_var))
            kl_loss = tf.reduce_mean(tf.reduce_sum(kl_loss, axis=1))
            total_loss = reconstruction_loss + kl_loss
        grads = tape.gradient(total_loss, self.trainable_weights)
        self.optimizer.apply_gradients(zip(grads, self.trainable_weights))
        self.total_loss_tracker.update_state(total_loss)
        self.precision.update_state(outputs, inputs)
        self.accuracy.update_state(outputs, inputs)
        return {
            "loss": self.total_loss_tracker.result(),
            'pre': self.precision.result(),
            'acc': self.accuracy.result()
        }

    def test_step(self, data):
        inputs, outputs = data
        z_mean, z_log_var, z = self.encoder(inputs)
        reconstruction = self.decoder(z)
        y_true, _ = tf.split(outputs, [reconstruction.shape[1], 1], axis=-1)
        reconstruction_loss = tf.math.sqrt(tf.reduce_sum(tf.square(y_true - reconstruction), axis=-1))
        kl_loss = - 0.5 * (1 + z_log_var - tf.square(z_mean) - tf.exp(z_log_var))
        kl_loss = tf.reduce_mean(tf.reduce_sum(kl_loss, axis=1))
        total_loss = reconstruction_loss + kl_loss
        self.total_loss_tracker.update_state(total_loss)
        self.precision.update_state(outputs, inputs)
        self.accuracy.update_state(outputs, inputs)
        return {
            "loss": self.total_loss_tracker.result(),
            'pre': self.precision.result(),
            'acc': self.accuracy.result()
        }

def vae(nfeatures, nl, nh, dropout=0.5, batchnorm=True, lr=5e-5):
    model = VariationalAutoEncoder(nfeatures, nl, nh, dropout, batchnorm)
    model.build((None, nfeatures - 1))
    model.compile(optimizer=tf.keras.optimizers.Adam(lr=lr), loss=ae_reconstruction_loss)
    return model, 'vae_{0}_{1}'.format(nl, nh)

class MLPLayer(tf.keras.layers.Layer):

    def __init__(self, nl, nh, dropout, batchnorm):
        super(MLPLayer, self).__init__()
        self.layers = []
        if batchnorm:
            norm = tf.keras.layers.BatchNormalization()
            self.layers.append(norm)
        for i in range(nl):
            self.layers.append(tf.keras.layers.Dense(nh, activation='relu'))
            if dropout is not None:
                self.layers.append(tf.keras.layers.Dropout(dropout))

    def call(self, inputs):
        x = inputs
        for layer in self.layers:
            x = layer(x)
        return x


class SOMLayer(tf.keras.layers.Layer):

    def __init__(self, map_size, prototypes=None, **kwargs):
        if 'input_shape' not in kwargs and 'latent_dim' in kwargs:
            kwargs['input_shape'] = (kwargs.pop('latent_dim'),)
        super(SOMLayer, self).__init__(**kwargs)
        self.map_size = map_size
        self.nprototypes = np.prod(map_size)
        self.initial_prototypes = prototypes
        self.prototypes = None
        self.built = False

    def build(self, input_shape):
        input_dims = input_shape[1:]
        self.input_spec = tf.keras.layers.InputSpec(dtype=tf.float32, shape=(None, *input_dims))
        self.prototypes = self.add_weight(shape=(self.nprototypes, *input_dims), initializer='glorot_uniform', name='prototypes')
        if self.initial_prototypes is not None:
            self.set_weights(self.initial_prototypes)
            del self.initial_prototypes
        self.built = True

    def call(self, inputs, **kwargs):
        d = tf.reduce_mean(tf.reduce_sum(tf.square(tf.expand_dims(inputs, axis=1) - self.prototypes), axis=-1), axis=-1)
        return d

    def compute_output_shape(self, input_shape):
        assert(input_shape and len(input_shape) == 2)
        return input_shape[0], self.nprototypes

    def get_config(self):
        config = {'map_size': self.map_size}
        base_config = super(SOMLayer, self).get_config()
        return dict(list(base_config.items()) + list(config.items()))

def som_loss(weights, distances):
    return tf.reduce_mean(tf.reduce_sum(weights * distances, axis=1))

class SOM(tf.keras.models.Model):

    def __init__(self, map_size, batchnorm, T_min=0.1, T_max=10.0, niterations=10000, nnn=4):
        super(SOM, self).__init__()
        self.map_size = map_size
        self.nprototypes = np.prod(map_size)
        ranges = [np.arange(m) for m in map_size]
        mg = np.meshgrid(*ranges, indexing='ij')
        self.prototype_coordinates = tf.convert_to_tensor(np.array([item.flatten() for item in mg]).T)
        self.bn_layer = tf.keras.layers.BatchNormalization(trainable=batchnorm)
        self.som_layer = SOMLayer(map_size, name='som_layer')
        self.T_min = T_min
        self.T_max = T_max
        self.niterations = niterations
        self.current_iteration = 0
        self.total_loss_tracker = tf.keras.metrics.Mean(name='total_loss')
        self.nnn = nnn

    @property
    def prototypes(self):
        return self.som_layer.get_weights()[0]

    def call(self, x):
        x = self.bn_layer(x)
        x = self.som_layer(x)
        s = tf.sort(x, axis=1)
        spl = tf.split(s, [self.nnn, self.nprototypes - self.nnn], axis=1)
        return tf.reduce_mean(spl[0], axis=1)

    def map_dist(self, y_pred):
        labels = tf.gather(self.prototype_coordinates, y_pred)
        mh = tf.reduce_sum(tf.math.abs(tf.expand_dims(labels, 1) - tf.expand_dims(self.prototype_coordinates, 0)), axis=-1)
        return tf.cast(mh, tf.float32)

    @staticmethod
    def neighborhood_function(d, T):
        return tf.math.exp(-(d ** 2) / (T ** 2))

    def train_step(self, data):
        inputs, outputs = data
        with tf.GradientTape() as tape:

            # Compute cluster assignments for batches

            inputs = self.bn_layer(inputs)
            d = self.som_layer(inputs)
            y_pred = tf.math.argmin(d, axis=1)

            # Update temperature parameter

            self.current_iteration += 1
            if self.current_iteration > self.niterations:
                self.current_iteration = self.niterations
            self.T = self.T_max * (self.T_min / self.T_max) ** (self.current_iteration / (self.niterations - 1))

            # Compute topographic weights batches

            w_batch = self.neighborhood_function(self.map_dist(y_pred), self.T)

            # calculate loss

            loss = som_loss(w_batch, d)

        grads = tape.gradient(loss, self.trainable_weights)
        self.optimizer.apply_gradients(zip(grads, self.trainable_weights))
        self.total_loss_tracker.update_state(loss)
        return {
            "total_loss": self.total_loss_tracker.result()
        }

    def test_step(self, data):
        inputs, outputs = data
        inputs = self.bn_layer(inputs)
        d = self.som_layer(inputs)
        y_pred = tf.math.argmin(d, axis=1)
        w_batch = self.neighborhood_function(self.map_dist(y_pred), self.T)
        loss = som_loss(w_batch, d)
        self.total_loss_tracker.update_state(loss)
        return {
            "total_loss": self.total_loss_tracker.result()
        }

def som(nsteps, nfeatures, layers=[64, 64], dropout=0.5, batchnorm=True, lr=5e-5):
    model = SOM(layers, dropout, batchnorm)
    model.build(input_shape=(None, nsteps, nfeatures))
    model.compile(optimizer=tf.keras.optimizers.Adam(lr=lr))
    return model, 'som_{0}'.format('-'.join([str(item) for item in layers])), 'ad'

class BGNGenerator(tf.keras.layers.Layer):

    def __init__(self, nsteps, nfeatures, layers=[512], kernel_size=2, **kwargs):
        super(BGNGenerator, self).__init__(**kwargs)
        self.hiddens = []
        for nfilters in layers:
            self.hiddens.append(tf.keras.layers.Conv1DTranspose(filters=nfilters, kernel_size=kernel_size))
        self.output_layer = tf.keras.layers.Conv1DTranspose(filters=nfeatures, kernel_size=nsteps-len(layers))

    def call(self, inputs, **kwargs):
        x = inputs
        for hidden in self.hiddens:
            x = hidden(x)
        x = self.output_layer(x)
        return x

class BGNDiscriminator(tf.keras.layers.Layer):

    def __init__(self, layers=[512], kernel_size=2, **kwargs):
        super(BGNDiscriminator, self).__init__(**kwargs)
        self.hiddens = layers
        self.convs = []
        for nh in self.hiddens:
            self.convs.append(tf.keras.layers.Conv1D(filters=nh, kernel_size=kernel_size))
        self.flat = tf.keras.layers.Flatten()
        self.outputs = tf.keras.layers.Dense(1, activation='sigmoid')

    def call(self, inputs, **kwargs):
        h = inputs
        for conv in self.convs:
            h = conv(h)
        h = self.flat(h)
        h = self.outputs(h)
        return h[:, 0]

class BGN(tf.keras.models.Model):

    def __init__(self, nsteps, nfeatures, latent_dim, layers, kernel_size=2):
        super(BGN, self).__init__()
        self.nsteps = nsteps
        self.nfeatures = nfeatures
        self.latent_dim = tf.constant(latent_dim)
        self.filters = layers

        # generator

        self.generator_layers = []
        for nfilters in layers[:-1]:
            self.generator_layers.append(tf.keras.layers.Conv1DTranspose(filters=nfilters, kernel_size=kernel_size))
        self.generator_layers.append(tf.keras.layers.Conv1DTranspose(filters=nfeatures, kernel_size=nsteps - len(layers) + 1))

        # discriminator

        self.discriminator_layers = []
        for nfilters in layers:
            self.discriminator_layers.append(tf.keras.layers.Conv1D(filters=nfilters, kernel_size=kernel_size))
        self.discriminator_layers.append(tf.keras.layers.Flatten())
        self.discriminator_layers.append(tf.keras.layers.Dense(1, activation='sigmoid'))

        # loss trackers

        self.g_loss_tracker = tf.keras.metrics.Mean(name='g_loss')
        self.d_loss_tracker = tf.keras.metrics.Mean(name='d_loss')

        self.built = False

    def build(self, input_shape):

        # generator

        self.generator_trainable_variables = []
        self.generator_layers[0].build(input_shape)
        for i in range(len(self.filters) - 1):
            self.generator_layers[i + 1].build(input_shape=(None, i + 2, self.filters[i]))
        for i in range(len(self.generator_layers)):
            self.generator_trainable_variables.extend(self.generator_layers[i].trainable_variables)

        # discriminator

        self.discriminator_trainable_variables = []
        self.discriminator_layers[0].build((None, self.nsteps, self.nfeatures))
        for i in range(len(self.filters)):
            self.discriminator_layers[i + 1].build(input_shape=(None, self.nsteps - i - 1, self.filters[i]))
        self.discriminator_layers[-1].build(input_shape=(None, (self.nsteps - len(self.filters)) * self.filters[-1]))
        for i in range(len(self.discriminator_layers)):
            self.discriminator_trainable_variables.extend(self.discriminator_layers[i].trainable_variables)
        self.built = True

    def call(self, x):
        for layer in self.discriminator_layers:
            x = layer(x)
        score = tf.nn.sigmoid_cross_entropy_with_logits(labels=tf.ones_like(x), logits=x)
        return score[:, 0]

    def train_step(self, data):
        x_real, z_with_label = data
        z, _ = tf.split(z_with_label, [self.latent_dim, 1], axis=1)
        z = tf.expand_dims(z, 1)
        x_fake = z
        for layer in self.generator_layers:
            x_fake = layer(x_fake)
        d_preds = tf.concat([x_fake, x_real], axis=0)
        for layer in self.discriminator_layers:
            d_preds = layer(d_preds)
        pred_g, pred_e = tf.split(d_preds, num_or_size_splits=2, axis=0)
        d_loss = tf.reduce_mean(tf.nn.softplus(pred_g)) + tf.reduce_mean(tf.nn.softplus(-pred_e))
        g_loss = tf.reduce_mean(tf.nn.softplus(-pred_g))
        d_gradients = tf.gradients(d_loss, self.discriminator_trainable_variables)
        g_gradients = tf.gradients(g_loss, self.generator_trainable_variables)
        self.optimizer.apply_gradients(zip(d_gradients, self.discriminator_trainable_variables))
        self.optimizer.apply_gradients(zip(g_gradients, self.generator_trainable_variables))
        self.g_loss_tracker.update_state(g_loss)
        self.d_loss_tracker.update_state(d_loss)

        return {
            "g_loss": self.g_loss_tracker.result(),
            "d_loss": self.d_loss_tracker.result(),
        }

        return d_loss, g_loss

    def test_step(self, data):
        x_real, z_with_label = data
        z, _ = tf.split(z_with_label, [self.latent_dim, 1], axis=1)
        z = tf.expand_dims(z, 1)
        x_fake = z
        for layer in self.generator_layers:
            x_fake = layer(x_fake)
        d_preds = tf.concat([x_fake, x_real], axis=0)
        for layer in self.discriminator_layers:
            d_preds = layer(d_preds)
        pred_g, pred_e = tf.split(d_preds, num_or_size_splits=2, axis=0)

        d_loss = tf.reduce_mean(tf.nn.softplus(pred_g)) + tf.reduce_mean(tf.nn.softplus(-pred_e))
        g_loss = tf.reduce_mean(tf.nn.softplus(-pred_g))

        self.g_loss_tracker.update_state(g_loss)
        self.d_loss_tracker.update_state(d_loss)

        return {
            "g_loss": self.g_loss_tracker.result(),
            "d_loss": self.d_loss_tracker.result(),
        }

        return d_loss, g_loss


def bgn(nsteps, nfeatures, layers=[512, 512], latent_dim=gan_latent_dim, lr=5e-5):
    model = BGN(nsteps, nfeatures, latent_dim, layers)
    #model.build(input_shape=(None, nsteps, nfeatures))
    model.build(input_shape=(None, 1, latent_dim))
    model.compile(optimizer=tf.keras.optimizers.Adam(lr=lr))
    return model, 'bgn_{0}'.format('-'.join([str(item) for item in layers])), 'ad'
