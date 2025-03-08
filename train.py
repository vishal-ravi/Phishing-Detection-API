import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import joblib
import os

from preprocessing.url_features import extract_url_features
from preprocessing.text_features import extract_text_features
from models.phishing_classifier import URLPhishingClassifier, EmailPhishingClassifier
import spacy

def load_and_preprocess_url_data(data_path):
    """Load and preprocess URL dataset."""
    try:
        # First read all columns as strings to avoid conversion errors
        df = pd.read_csv(
            data_path,
            encoding='latin1',
            dtype=str,  # Read all columns as strings initially
            on_bad_lines='skip'
        )
        print(f"Successfully loaded dataset with {len(df)} rows")
        
        # Function to safely convert to float
        def safe_float_convert(x):
            try:
                return float(x)
            except (ValueError, TypeError):
                return np.nan
        
        # Convert numeric columns safely
        numeric_columns = [
            'ranking', 'mld_res', 'mld.ps_res', 'card_rem', 
            'ratio_Rrem', 'ratio_Arem', 'jaccard_RR', 'jaccard_RA',
            'jaccard_AR', 'jaccard_AA', 'jaccard_ARrd', 'jaccard_ARrem',
            'label'
        ]
        
        # Convert each numeric column safely
        for col in numeric_columns:
            if col in df.columns:
                df[col] = df[col].apply(safe_float_convert)
        
        # Drop rows with NaN values in numeric columns
        df = df.dropna(subset=numeric_columns)
        print(f"After cleaning numeric data: {len(df)} rows")
        
        # Reset index to ensure proper alignment
        df = df.reset_index(drop=True)
        
        # Process URLs and create features
        print("Extracting features from URLs...")
        url_features = []
        valid_indices = []
        
        for idx, url in enumerate(df['domain']):
            try:
                if pd.isna(url) or not isinstance(url, str):
                    continue
                features = extract_url_features(url)
                url_features.append(features)
                valid_indices.append(idx)
            except Exception as e:
                print(f"Warning: Skipping malformed URL at index {idx}: {url[:100]}... Error: {str(e)}")
                continue
        
        if not url_features:
            raise ValueError("No valid URLs could be processed")
        
        print(f"Successfully processed {len(url_features)} URLs")
        
        # Convert URL features to DataFrame with proper index
        url_features_df = pd.DataFrame(url_features, index=valid_indices)
        
        # Select numerical features for valid indices
        numerical_features = df.loc[valid_indices, numeric_columns[:-1]].copy()  # Exclude 'label'
        
        # Combine features
        X = pd.concat([url_features_df, numerical_features], axis=1)
        y = df.loc[valid_indices, 'label'].astype(float)
        
        print(f"Final dataset shape: {X.shape}")
        print(f"Features include: {X.columns.tolist()}")
        print(f"Label distribution: \n{y.value_counts(normalize=True)}")
        
        if len(X) == 0:
            raise ValueError("No valid samples remaining after preprocessing")
        
        return X, y
        
    except Exception as e:
        print(f"Error processing dataset: {str(e)}")
        raise

def load_and_preprocess_email_data(data_path):
    """Load and preprocess email dataset."""
    try:
        # Load spaCy model
        nlp = spacy.load('en_core_web_sm')
        
        # Load dataset with all columns as strings initially
        df = pd.read_csv(
            data_path,
            encoding='latin1',
            dtype=str,
            on_bad_lines='skip'
        )
        print(f"Successfully loaded email dataset with {len(df)} rows")
        
        # Print available columns to help debugging
        print("Available columns:", df.columns.tolist())
        
        # Determine the text content column (try common names)
        content_column = None
        possible_content_columns = ['text_combined', 'content', 'text', 'email', 'message', 'body', 'domain']
        for col in possible_content_columns:
            if col in df.columns:
                content_column = col
                break
        
        if content_column is None:
            raise ValueError(f"Could not find text content column. Available columns: {df.columns.tolist()}")
        
        print(f"Using '{content_column}' as content column")
        
        # Process emails and create features
        print("Extracting features from emails...")
        features = []
        valid_indices = []
        
        for idx, text in enumerate(df[content_column]):
            try:
                if pd.isna(text) or not isinstance(text, str):
                    continue
                email_features = extract_text_features(text, nlp)
                features.append(email_features)
                valid_indices.append(idx)
                
                # Print progress every 1000 emails
                if (idx + 1) % 1000 == 0:
                    print(f"Processed {idx + 1} emails...")
                    
            except Exception as e:
                print(f"Warning: Skipping malformed email at index {idx}. Error: {str(e)}")
                continue
        
        if not features:
            raise ValueError("No valid emails could be processed")
        
        print(f"Successfully processed {len(features)} emails")
        
        # Convert to DataFrame
        X = pd.DataFrame(features)
        
        # Convert labels safely
        y = pd.Series([float(label) if label in ['0', '1'] else np.nan 
                      for label in df.loc[valid_indices, 'label']])
        
        # Remove any samples with invalid labels
        valid_label_mask = ~y.isna()
        X = X[valid_label_mask]
        y = y[valid_label_mask]
        
        print(f"Final dataset shape: {X.shape}")
        print(f"Features include: {X.columns.tolist()}")
        print(f"Label distribution: \n{y.value_counts(normalize=True)}")
        
        if len(X) == 0:
            raise ValueError("No valid samples remaining after preprocessing")
        
        return X, y
        
    except Exception as e:
        print(f"Error processing email dataset: {str(e)}")
        raise

def train_url_model(data_path, model_save_path, vectorizer_save_path):
    """Train URL phishing detection model."""
    # Load and preprocess data
    X, y = load_and_preprocess_url_data(data_path)
    
    # Create directory for models if it doesn't exist
    os.makedirs(os.path.dirname(model_save_path), exist_ok=True)
    os.makedirs(os.path.dirname(vectorizer_save_path), exist_ok=True)
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Save scaler
    joblib.dump(scaler, vectorizer_save_path)
    print(f"Saved feature scaler to {vectorizer_save_path}")
    
    # Train model
    model = URLPhishingClassifier(input_dim=X_train_scaled.shape[1])
    history = model.fit(
        X_train_scaled, y_train,
        validation_data=(X_test_scaled, y_test),
        epochs=20,
        batch_size=32
    )
    
    # Save model
    model.save(model_save_path)
    print(f"Saved trained model to {model_save_path}")
    
    # Evaluate
    loss, accuracy, auc = model.evaluate(X_test_scaled, y_test)
    print(f'Test accuracy: {accuracy:.4f}')
    print(f'Test AUC: {auc:.4f}')
    
    return model, history

def train_email_model(data_path, model_save_path, vectorizer_save_path):
    """Train email phishing detection model."""
    # Load and preprocess data
    X, y = load_and_preprocess_email_data(data_path)
    
    # Create directory for models if it doesn't exist
    os.makedirs(os.path.dirname(model_save_path), exist_ok=True)
    os.makedirs(os.path.dirname(vectorizer_save_path), exist_ok=True)
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Save scaler
    joblib.dump(scaler, vectorizer_save_path)
    print(f"Saved feature scaler to {vectorizer_save_path}")
    
    # Train model
    model = EmailPhishingClassifier(input_dim=X_train_scaled.shape[1])
    history = model.fit(
        X_train_scaled, y_train,
        validation_data=(X_test_scaled, y_test),
        epochs=20,
        batch_size=32
    )
    
    # Save model
    model.save(model_save_path)
    print(f"Saved trained model to {model_save_path}")
    
    # Evaluate
    loss, accuracy, auc = model.evaluate(X_test_scaled, y_test)
    print(f'Test accuracy: {accuracy:.4f}')
    print(f'Test AUC: {auc:.4f}')
    
    return model, history

if __name__ == '__main__':
    # Train URL model
    print("Training URL model...")
    url_model, url_history = train_url_model(
        'data/url_dataset.csv',
        'models/url_model',
        'models/url_vectorizer.pkl'
    )
    
    # Train email model
    print("\nTraining email model...")
    email_model, email_history = train_email_model(
        'data/email_dataset.csv',
        'models/email_model',
        'models/text_vectorizer.pkl'
    ) 