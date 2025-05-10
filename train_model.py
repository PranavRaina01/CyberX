import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import joblib
import logging
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('model_training.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class CyberSecurityModel:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.feature_names = [
            'protocol_type', 'service', 'src_bytes', 'dst_bytes',
            'duration', 'bytes_ratio', 'total_bytes', 'bytes_per_second'
        ]

    def preprocess_data(self, X):
        """
        Preprocess input data with validation
        """
        try:
            if not isinstance(X, (np.ndarray, pd.DataFrame)):
                raise ValueError("Input must be numpy array or pandas DataFrame")

            if isinstance(X, pd.DataFrame):
                X = X.to_numpy()

            if X.shape[1] != len(self.feature_names):
                raise ValueError(f"Expected {len(self.feature_names)} features, got {X.shape[1]}")

            if self.scaler is None:
                self.scaler = StandardScaler()
                                                 X_scaled = self.scaler.fit_transform(X)
            else:
                X_scaled = self.scaler.transform(X)

            return X_scaled

        except Exception as e:
            logger.error(f"Error in preprocessing: {str(e)}")
            raise

    def train(self, X, y):
        """
        Train the model with input validation
        """
        try:
            if len(X) != len(y):
                raise ValueError("X and y must have the same length")

            if not isinstance(y, (np.ndarray, pd.Series)):
                raise ValueError("y must be numpy array or pandas Series")

            X_scaled = self.preprocess_data(X)
            
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42
            )
            
            self.model.fit(X_scaled, y)
            logger.info("Model training completed successfully")

        except Exception as e:
            logger.error(f"Error in training: {str(e)}")
            raise

    def predict(self, X):
        """
        Make predictions with confidence scores
        """
        try:
            if self.model is None:
                raise ValueError("Model not trained or loaded")

            X_scaled = self.preprocess_data(X)
            predictions = self.model.predict(X_scaled)
            probabilities = self.model.predict_proba(X_scaled)
            
            # Get confidence scores for the predicted class
            confidences = np.max(probabilities, axis=1)
            
            return predictions, confidences

        except Exception as e:
            logger.error(f"Error in prediction: {str(e)}")
            raise

    def save_model(self, filepath):
        """
        Save model to file with validation
        """
        try:
            if self.model is None:
                raise ValueError("No model to save")

            if not filepath.endswith('.pkl'):
                filepath += '.pkl'

            model_data = {
                'model': self.model,
                'scaler': self.scaler,
                'feature_names': self.feature_names
            }
            
            joblib.dump(model_data, filepath)
            logger.info(f"Model saved successfully to {filepath}")

        except Exception as e:
            logger.error(f"Error saving model: {str(e)}")
            raise

    @classmethod
    def load_model(cls, filepath):
        """
        Load model from file with validation
        """
        try:
            if not os.path.exists(filepath):
                raise FileNotFoundError(f"Model file not found: {filepath}")

            model_data = joblib.load(filepath)
            
            if not isinstance(model_data, dict) or \
               not all(key in model_data for key in ['model', 'scaler', 'feature_names']):
                raise ValueError("Invalid model file format")

            instance = cls()
            instance.model = model_data['model']
            instance.scaler = model_data['scaler']
            instance.feature_names = model_data['feature_names']
            
            logger.info(f"Model loaded successfully from {filepath}")
            return instance

        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
            raise

if __name__ == '__main__':
    try:
        # Example training code
        data = pd.read_csv('UNSW_NB15.csv')
        
        # Prepare features and target
        X = data[['protocol_type', 'service', 'src_bytes', 'dst_bytes', 'duration']]
        
        # Add engineered features
        X['bytes_ratio'] = X['src_bytes'] / (X['dst_bytes'] + 1)
        X['total_bytes'] = X['src_bytes'] + X['dst_bytes']
        X['bytes_per_second'] = X['total_bytes'] / (X['duration'] + 1)
        
        y = data['attack']  # Assuming 'attack' is the target column
        
        # Split the data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )
        
        # Train and save model
        model = CyberSecurityModel()
        model.train(X_train, y_train)
        model.save_model('model.pkl')
        
        # Test predictions
        predictions, confidences = model.predict(X_test)
        accuracy = np.mean(predictions == y_test)
        logger.info(f"Model accuracy on test set: {accuracy:.4f}")

    except Exception as e:
        logger.error(f"Error in main training process: {str(e)}")
        raise