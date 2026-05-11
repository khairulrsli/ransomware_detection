from tensorflow.keras.models import Model
from tensorflow.keras.layers import (
    LSTM, Dense, Dropout, Embedding, Bidirectional,
    Conv1D, GlobalMaxPooling1D,
    BatchNormalization, SpatialDropout1D, Input,
    Concatenate,
    LayerNormalization, Add, MultiHeadAttention
)
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.regularizers import l2


def build_lstm(vocab_size=50, embedding_dim=64, max_length=200):
    """
    Advanced Attention-CNN-BiLSTM hybrid for ransomware detection.

    Architecture:
        1. Embedding → SpatialDropout
        2. Multi-scale 1D CNN (kernel 3,5,7) for local n-gram feature extraction
        3. Stacked BiLSTM with residual connections for temporal pattern learning
        4. Multi-Head Self-Attention for long-range dependency capture
        5. Dense classifier with BatchNorm and heavy dropout

    This architecture captures:
        - Local patterns: CNN extracts n-gram features (e.g. OpenFile→BusyLoop→WriteFile)
        - Temporal patterns: BiLSTM captures sequential ordering dependencies
        - Long-range dependencies: Attention links early reconnaissance to late encryption
    """
    inputs = Input(shape=(max_length,), name='api_sequence')

    # ── EMBEDDING LAYER ──────────────────────────────────────────────────────
    x = Embedding(
        vocab_size, embedding_dim,
        input_length=max_length,
        mask_zero=False,
        name='event_embedding'
    )(inputs)
    x = SpatialDropout1D(0.2, name='spatial_dropout')(x)

    # ── MULTI-SCALE 1D CNN — local n-gram feature extraction ─────────────
    # Three parallel convolutions with different kernel sizes capture
    # different-length behavioral motifs (trigrams, pentagrams, heptagrams)
    conv3 = Conv1D(64, 3, padding='same', activation='relu', name='conv_3gram')(x)
    conv5 = Conv1D(64, 5, padding='same', activation='relu', name='conv_5gram')(x)
    conv7 = Conv1D(64, 7, padding='same', activation='relu', name='conv_7gram')(x)

    # Merge CNN outputs → richer local feature representation
    cnn_merged = Concatenate(name='cnn_merge')([conv3, conv5, conv7])
    cnn_merged = BatchNormalization(name='cnn_batchnorm')(cnn_merged)
    cnn_merged = Dropout(0.3, name='cnn_dropout')(cnn_merged)

    # ── STACKED BiLSTM — temporal sequence modeling ──────────────────────
    lstm1 = Bidirectional(
        LSTM(128, return_sequences=True, dropout=0.3, recurrent_dropout=0.2,
             kernel_regularizer=l2(1e-5)),
        name='bilstm_1'
    )(cnn_merged)
    lstm1 = BatchNormalization(name='lstm1_batchnorm')(lstm1)

    lstm2 = Bidirectional(
        LSTM(64, return_sequences=True, dropout=0.3, recurrent_dropout=0.2,
             kernel_regularizer=l2(1e-5)),
        name='bilstm_2'
    )(lstm1)
    lstm2 = BatchNormalization(name='lstm2_batchnorm')(lstm2)

    # ── MULTI-HEAD SELF-ATTENTION — long-range dependency capture ────────
    # Links early file enumeration to later encryption activity
    attention_output = MultiHeadAttention(
        num_heads=4, key_dim=32, dropout=0.2, name='multihead_attention'
    )(lstm2, lstm2)
    attention_output = LayerNormalization(name='attention_layernorm')(attention_output)
    attention_output = Add(name='attention_residual')([lstm2, attention_output])

    # Global pooling to collapse temporal dimension
    pooled = GlobalMaxPooling1D(name='global_max_pool')(attention_output)

    # ── CLASSIFIER HEAD ──────────────────────────────────────────────────
    dense1 = Dense(128, activation='relu', kernel_regularizer=l2(1e-4), name='dense_1')(pooled)
    dense1 = BatchNormalization(name='dense1_batchnorm')(dense1)
    dense1 = Dropout(0.5, name='dense1_dropout')(dense1)

    dense2 = Dense(64, activation='relu', kernel_regularizer=l2(1e-4), name='dense_2')(dense1)
    dense2 = BatchNormalization(name='dense2_batchnorm')(dense2)
    dense2 = Dropout(0.4, name='dense2_dropout')(dense2)

    dense3 = Dense(32, activation='relu', name='dense_3')(dense2)
    dense3 = Dropout(0.3, name='dense3_dropout')(dense3)

    output = Dense(1, activation='sigmoid', name='prediction')(dense3)

    model = Model(inputs=inputs, outputs=output, name='RansomwareDetector_v3')

    model.compile(
        optimizer=Adam(learning_rate=0.001),
        loss='binary_crossentropy',
        metrics=['accuracy']
    )

    return model
