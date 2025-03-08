import tensorflow as tf
from tensorflow.keras import layers, models
import numpy as np
from sklearn.base import BaseEstimator, ClassifierMixin

class PhishingClassifier:
    def __init__(self, input_dim, model_type='url'):
        self.input_dim = input_dim
        self.model_type = model_type
        self.model = self._build_model()
        
    def _build_model(self):
        """Build neural network model architecture."""
        model = models.Sequential([
            # Input layer with batch normalization
            layers.Dense(128, input_dim=self.input_dim),
            layers.BatchNormalization(),
            layers.Activation('relu'),
            layers.Dropout(0.3),
            
            # Hidden layers
            layers.Dense(64),
            layers.BatchNormalization(),
            layers.Activation('relu'),
            layers.Dropout(0.2),
            
            layers.Dense(32),
            layers.BatchNormalization(),
            layers.Activation('relu'),
            layers.Dropout(0.2),
            
            # Output layer
            layers.Dense(1, activation='sigmoid')
        ])
        
        model.compile(
            optimizer=tf.keras.optimizers.Adam(learning_rate=0.001),
            loss='binary_crossentropy',
            metrics=['accuracy', tf.keras.metrics.AUC()]
        )
        
        return model
    
    def fit(self, X, y, validation_data=None, epochs=10, batch_size=32):
        """Train the model on the provided data."""
        # Add early stopping to prevent overfitting
        early_stopping = tf.keras.callbacks.EarlyStopping(
            monitor='val_loss',
            patience=5,
            restore_best_weights=True
        )
        
        # Add learning rate reduction on plateau
        reduce_lr = tf.keras.callbacks.ReduceLROnPlateau(
            monitor='val_loss',
            factor=0.2,
            patience=3,
            min_lr=0.00001
        )
        
        return self.model.fit(
            X, y,
            validation_data=validation_data,
            epochs=epochs,
            batch_size=batch_size,
            callbacks=[early_stopping, reduce_lr],
            verbose=1
        )
    
    def predict(self, X):
        """Generate predictions for input data."""
        return self.model.predict(X)
    
    def evaluate(self, X, y):
        """Evaluate model performance."""
        return self.model.evaluate(X, y)
    
    def save(self, filepath):
        """Save the model to disk."""
        self.model.save(filepath)
    
    @classmethod
    def load(cls, filepath):
        """Load a saved model from disk."""
        model = tf.keras.models.load_model(filepath)
        instance = cls(model.input_shape[1])
        instance.model = model
        return instance

class URLPhishingClassifier(PhishingClassifier):
    def __init__(self, input_dim):
        super().__init__(input_dim, model_type='url')
        
    def preprocess_features(self, features):
        """Preprocess URL features before prediction."""
        # Add any URL-specific preprocessing here
        return features

class EmailPhishingClassifier(PhishingClassifier):
    def __init__(self, input_dim):
        super().__init__(input_dim, model_type='email')
        
    def preprocess_features(self, features):
        """Preprocess email features before prediction."""
        # Add any email-specific preprocessing here
        return features 