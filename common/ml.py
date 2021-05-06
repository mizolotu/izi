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

def load_batches_for_anomaly_detection(path, batch_size, nfeatures):
    batches = tf.data.experimental.make_csv_dataset(
        path,
        batch_size=batch_size,
        header=False,
        shuffle=True,
        column_names=[str(i) for i in range(nfeatures)],
        column_defaults=[tf.float32 for _ in range(nfeatures)],
        select_columns=[str(i) for i in range(nfeatures)]
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

def anomaly_detection_mapper(features, labels, xmin, xmax, eps=1e-10):
    features = (tf.stack(list(features.values()), axis=-1) - xmin) / (xmax - xmin + eps)
    features_with_labels = tf.concat([features, tf.reshape(labels, (-1, 1))], axis=1)
    return features, features_with_labels

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
    model.compile(loss=tf.keras.losses.BinaryCrossentropy(), optimizer=tf.keras.optimizers.Adam(lr=lr), metrics=[tf.keras.metrics.AUC(name='auc'), tf.keras.metrics.BinaryAccuracy(name='accuracy'), tf.keras.metrics.Precision(name='precision')])
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

def ae_reconstruction_loss(y_true, y_pred):
    y_true, _ = tf.split(y_true, [y_pred.shape[1], 1], axis=1)
    squared_difference = tf.square(y_true - y_pred)
    return tf.math.sqrt(tf.reduce_sum(squared_difference, axis=-1))

class ReconstructionAuc(tf.keras.metrics.Metric):

    def __init__(self, name='reconstruction_auc', **kwargs):
        super(ReconstructionAuc, self).__init__(name=name, **kwargs)
        self.auc = tf.keras.metrics.AUC()
        self.reconstruction_errors = tf.Variable([], shape=(None,), validate_shape=False)
        self.true_labels = tf.Variable([], shape=(None,), validate_shape=False)

    def update_state(self, y_true, y_pred, sample_weight=None):
        y_true, label_true = tf.split(y_true, [y_pred.shape[1], 1], axis=1)
        label_true = tf.clip_by_value(label_true, 0, 1)
        reconstruction_errors = tf.math.sqrt(tf.reduce_sum(tf.square(y_true - y_pred), axis=-1))
        self.reconstruction_errors.assign(tf.concat([self.reconstruction_errors.value(), reconstruction_errors], axis=0))
        self.true_labels.assign(tf.concat([self.true_labels.value(), label_true[:, 0]], axis=0))

    def result(self):
        probs = self.reconstruction_errors / (tf.reduce_sum(self.reconstruction_errors) + 1)
        self.auc.update_state(self.true_labels, probs)
        return self.auc.result()

    def reset_states(self):
        self.reconstruction_errors.assign([])
        self.true_labels.assign([])
        self.auc.reset_states()

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

def ae(nfeatures, nl, nh, alpha, dropout=0.5, batchnorm=True, lr=5e-5):
    inputs = tf.keras.layers.Input(shape=(nfeatures - 1,))
    if batchnorm:
        norm = tf.keras.layers.BatchNormalization()
        hidden = norm(inputs)
    else:
        hidden = inputs
    for i in range(nl):
        hidden = tf.keras.layers.Dense(nh, activation='relu')(hidden)
        if dropout is not None:
            hidden = tf.keras.layers.Dropout(dropout)(hidden)
    hidden = tf.keras.layers.Dense(nfeatures - 1, activation='relu')(hidden)
    for _ in range(nl):
        hidden = tf.keras.layers.Dense(nh, activation='relu')(hidden)
        if dropout is not None:
            hidden = tf.keras.layers.Dropout(dropout)(hidden)
        outputs = tf.keras.layers.Dense(nfeatures - 1, activation='sigmoid')(hidden)
        model = tf.keras.models.Model(inputs=inputs, outputs=outputs)
        model.compile(loss=ae_reconstruction_loss, optimizer=tf.keras.optimizers.Adam(lr=lr), metrics=[
            ReconstructionPrecision(name='pre', alpha=alpha), ReconstructionAccuracy(name='acc', alpha=alpha), ReconstructionAuc(name='auc')
        ])
    return model, 'ae_{0}_{1}'.format(nl, nh)

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