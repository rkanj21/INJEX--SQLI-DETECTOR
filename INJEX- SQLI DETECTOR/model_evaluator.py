"""
Model Evaluation Module for SQL Injection Detection
This module provides comprehensive evaluation metrics and visualizations
"""

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_curve, auc,
    precision_recall_curve, average_precision_score
)
import joblib
import json
from datetime import datetime
import os

class SQLInjectionModelEvaluator:
    """
    Comprehensive model evaluation with metrics and visualizations
    """
    
    def __init__(self, model_path='./Models/sql_injection_model.pkl', 
                 vectorizer_path='./Models/vectorizer.pkl'):
        """
        Initialize evaluator with saved model and vectorizer
        
        Args:
            model_path: Path to saved model file
            vectorizer_path: Path to saved vectorizer file
        """
        self.model = joblib.load(model_path)
        self.vectorizer = joblib.load(vectorizer_path)
        self.metrics = {}
        self.y_true = None
        self.y_pred = None
        self.y_pred_proba = None
    
    def evaluate_model(self, X_test, y_test, save_results=True, output_dir='evaluation_results'):
        """
        Perform complete evaluation on test data
        
        Args:
            X_test: Test features (raw text)
            y_test: True labels
            save_results: Whether to save results to files
            output_dir: Directory to save results
            
        Returns:
            dict: Dictionary containing all metrics
        """
        # Transform test data
        X_test_tfidf = self.vectorizer.transform(X_test)
        
        # Make predictions
        self.y_true = y_test
        self.y_pred = self.model.predict(X_test_tfidf)
        self.y_pred_proba = self.model.predict_proba(X_test_tfidf)[:, 1]
        
        # Calculate all metrics
        self._calculate_metrics()
        
        # Print results to console
        self.print_metrics()
        
        # Generate visualizations
        if save_results:
            os.makedirs(output_dir, exist_ok=True)
            self.plot_confusion_matrix(save_path=f'{output_dir}/confusion_matrix.png')
            self.plot_roc_curve(save_path=f'{output_dir}/roc_curve.png')
            self.plot_precision_recall_curve(save_path=f'{output_dir}/precision_recall_curve.png')
            self.plot_metrics_summary(save_path=f'{output_dir}/metrics_summary.png')
            self.save_metrics_json(f'{output_dir}/metrics.json')
            self.save_classification_report(f'{output_dir}/classification_report.txt')
            print(f"\n All evaluation results saved to '{output_dir}/' directory")
        
        return self.metrics
    
    def _calculate_metrics(self):
        """Calculate all evaluation metrics"""
        # Basic metrics
        self.metrics['accuracy'] = accuracy_score(self.y_true, self.y_pred)
        self.metrics['precision'] = precision_score(self.y_true, self.y_pred, zero_division=0)
        self.metrics['recall'] = recall_score(self.y_true, self.y_pred, zero_division=0)
        self.metrics['f1_score'] = f1_score(self.y_true, self.y_pred, zero_division=0)
        
        # Confusion matrix
        cm = confusion_matrix(self.y_true, self.y_pred)
        self.metrics['confusion_matrix'] = cm.tolist()
        
        # True/False Positives/Negatives
        tn, fp, fn, tp = cm.ravel()
        self.metrics['true_negatives'] = int(tn)
        self.metrics['false_positives'] = int(fp)
        self.metrics['false_negatives'] = int(fn)
        self.metrics['true_positives'] = int(tp)
        
        # Specificity (True Negative Rate)
        self.metrics['specificity'] = tn / (tn + fp) if (tn + fp) > 0 else 0
        
        # ROC AUC
        if self.y_pred_proba is not None:
            fpr, tpr, _ = roc_curve(self.y_true, self.y_pred_proba)
            self.metrics['roc_auc'] = auc(fpr, tpr)
            
            # Average Precision
            self.metrics['average_precision'] = average_precision_score(self.y_true, self.y_pred_proba)
        
        # Classification report as dict
        report = classification_report(self.y_true, self.y_pred, output_dict=True)
        self.metrics['classification_report'] = report
        
        # Add timestamp
        self.metrics['evaluation_timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def print_metrics(self):
        """Print formatted metrics to console"""
        print("\n" + "="*70)
        print("SQL INJECTION DETECTION MODEL - EVALUATION RESULTS")
        print("="*70)
        
        print(f"\n OVERALL PERFORMANCE METRICS:")
        print(f"{'Accuracy:':<25} {self.metrics['accuracy']:.4f} ({self.metrics['accuracy']*100:.2f}%)")
        print(f"{'Precision:':<25} {self.metrics['precision']:.4f} ({self.metrics['precision']*100:.2f}%)")
        print(f"{'Recall (Sensitivity):':<25} {self.metrics['recall']:.4f} ({self.metrics['recall']*100:.2f}%)")
        print(f"{'F1-Score:':<25} {self.metrics['f1_score']:.4f} ({self.metrics['f1_score']*100:.2f}%)")
        print(f"{'Specificity:':<25} {self.metrics['specificity']:.4f} ({self.metrics['specificity']*100:.2f}%)")
        
        if 'roc_auc' in self.metrics:
            print(f"{'ROC AUC Score:':<25} {self.metrics['roc_auc']:.4f} ({self.metrics['roc_auc']*100:.2f}%)")
            print(f"{'Average Precision:':<25} {self.metrics['average_precision']:.4f} ({self.metrics['average_precision']*100:.2f}%)")
        
        print(f"\n CONFUSION MATRIX BREAKDOWN:")
        print(f"{'True Positives (TP):':<25} {self.metrics['true_positives']}")
        print(f"{'True Negatives (TN):':<25} {self.metrics['true_negatives']}")
        print(f"{'False Positives (FP):':<25} {self.metrics['false_positives']}")
        print(f"{'False Negatives (FN):':<25} {self.metrics['false_negatives']}")
        
        print(f"\n DETAILED CLASSIFICATION REPORT:")
        report = self.metrics['classification_report']
        print(f"\n{'Class':<15} {'Precision':<12} {'Recall':<12} {'F1-Score':<12} {'Support':<12}")
        print("-" * 63)
        print(f"{'Safe (0)':<15} {report['0']['precision']:.4f}       {report['0']['recall']:.4f}       {report['0']['f1-score']:.4f}       {report['0']['support']}")
        print(f"{'SQL Injection (1)':<15} {report['1']['precision']:.4f}       {report['1']['recall']:.4f}       {report['1']['f1-score']:.4f}       {report['1']['support']}")
        
        print("\n" + "="*70)
    
    def plot_confusion_matrix(self, save_path=None):
        """Plot confusion matrix heatmap"""
        cm = np.array(self.metrics['confusion_matrix'])
        
        plt.figure(figsize=(10, 8))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                    xticklabels=['Safe (0)', 'SQL Injection (1)'],
                    yticklabels=['Safe (0)', 'SQL Injection (1)'],
                    cbar_kws={'label': 'Count'})
        plt.title('Confusion Matrix - SQL Injection Detection', fontsize=16, fontweight='bold', pad=20)
        plt.ylabel('True Label', fontsize=12, fontweight='bold')
        plt.xlabel('Predicted Label', fontsize=12, fontweight='bold')
        
        # Add percentages
        total = cm.sum()
        for i in range(2):
            for j in range(2):
                percentage = (cm[i, j] / total) * 100
                plt.text(j + 0.5, i + 0.7, f'({percentage:.1f}%)', 
                        ha='center', va='center', fontsize=10, color='gray')
        
        plt.tight_layout()
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f" Confusion matrix saved: {save_path}")
        plt.close()
    
    def plot_roc_curve(self, save_path=None):
        """Plot ROC curve"""
        if self.y_pred_proba is None:
            print(" Cannot plot ROC curve: probability predictions not available")
            return
        
        fpr, tpr, thresholds = roc_curve(self.y_true, self.y_pred_proba)
        roc_auc = self.metrics['roc_auc']
        
        plt.figure(figsize=(10, 8))
        plt.plot(fpr, tpr, color='darkorange', lw=2, 
                label=f'ROC curve (AUC = {roc_auc:.4f})')
        plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--', 
                label='Random Classifier (AUC = 0.5000)')
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel('False Positive Rate', fontsize=12, fontweight='bold')
        plt.ylabel('True Positive Rate', fontsize=12, fontweight='bold')
        plt.title('ROC Curve - SQL Injection Detection', fontsize=16, fontweight='bold', pad=20)
        plt.legend(loc="lower right", fontsize=11)
        plt.grid(alpha=0.3)
        
        plt.tight_layout()
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f" ROC curve saved: {save_path}")
        plt.close()
    
    def plot_precision_recall_curve(self, save_path=None):
        """Plot Precision-Recall curve"""
        if self.y_pred_proba is None:
            print(" Cannot plot PR curve: probability predictions not available")
            return
        
        precision, recall, _ = precision_recall_curve(self.y_true, self.y_pred_proba)
        avg_precision = self.metrics['average_precision']
        
        plt.figure(figsize=(10, 8))
        plt.plot(recall, precision, color='darkgreen', lw=2,
                label=f'PR curve (AP = {avg_precision:.4f})')
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel('Recall', fontsize=12, fontweight='bold')
        plt.ylabel('Precision', fontsize=12, fontweight='bold')
        plt.title('Precision-Recall Curve - SQL Injection Detection', 
                 fontsize=16, fontweight='bold', pad=20)
        plt.legend(loc="lower left", fontsize=11)
        plt.grid(alpha=0.3)
        
        plt.tight_layout()
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f" Precision-Recall curve saved: {save_path}")
        plt.close()
    
    def plot_metrics_summary(self, save_path=None):
        """Plot summary bar chart of all metrics"""
        metrics_to_plot = {
            'Accuracy': self.metrics['accuracy'],
            'Precision': self.metrics['precision'],
            'Recall': self.metrics['recall'],
            'F1-Score': self.metrics['f1_score'],
            'Specificity': self.metrics['specificity']
        }
        
        if 'roc_auc' in self.metrics:
            metrics_to_plot['ROC AUC'] = self.metrics['roc_auc']
        
        fig, ax = plt.subplots(figsize=(12, 7))
        bars = ax.bar(metrics_to_plot.keys(), metrics_to_plot.values(), 
                     color=['#2E86AB', '#A23B72', '#F18F01', '#C73E1D', '#6A994E', '#BC4B51'])
        
        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                   f'{height:.4f}\n({height*100:.2f}%)',
                   ha='center', va='bottom', fontsize=10, fontweight='bold')
        
        ax.set_ylim([0, 1.1])
        ax.set_ylabel('Score', fontsize=12, fontweight='bold')
        ax.set_title('Model Performance Metrics Summary', fontsize=16, fontweight='bold', pad=20)
        ax.grid(axis='y', alpha=0.3)
        plt.xticks(rotation=0, fontsize=11)
        
        plt.tight_layout()
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f" Metrics summary saved: {save_path}")
        plt.close()
    
    def save_metrics_json(self, filepath):
        """Save metrics to JSON file"""
        # Convert numpy types to Python types for JSON serialization
        metrics_copy = self.metrics.copy()
        
        with open(filepath, 'w') as f:
            json.dump(metrics_copy, f, indent=4)
        print(f" Metrics JSON saved: {filepath}")
    
    def save_classification_report(self, filepath):
        """Save detailed classification report to text file"""
        with open(filepath, 'w') as f:
            f.write("="*70 + "\n")
            f.write("SQL INJECTION DETECTION MODEL - DETAILED EVALUATION REPORT\n")
            f.write("="*70 + "\n\n")
            
            f.write(f"Evaluation Timestamp: {self.metrics['evaluation_timestamp']}\n\n")
            
            f.write("OVERALL PERFORMANCE METRICS:\n")
            f.write("-" * 70 + "\n")
            f.write(f"Accuracy:               {self.metrics['accuracy']:.4f} ({self.metrics['accuracy']*100:.2f}%)\n")
            f.write(f"Precision:              {self.metrics['precision']:.4f} ({self.metrics['precision']*100:.2f}%)\n")
            f.write(f"Recall (Sensitivity):   {self.metrics['recall']:.4f} ({self.metrics['recall']*100:.2f}%)\n")
            f.write(f"F1-Score:               {self.metrics['f1_score']:.4f} ({self.metrics['f1_score']*100:.2f}%)\n")
            f.write(f"Specificity:            {self.metrics['specificity']:.4f} ({self.metrics['specificity']*100:.2f}%)\n")
            
            if 'roc_auc' in self.metrics:
                f.write(f"ROC AUC Score:          {self.metrics['roc_auc']:.4f} ({self.metrics['roc_auc']*100:.2f}%)\n")
                f.write(f"Average Precision:      {self.metrics['average_precision']:.4f} ({self.metrics['average_precision']*100:.2f}%)\n")
            
            f.write("\n\nCONFUSION MATRIX BREAKDOWN:\n")
            f.write("-" * 70 + "\n")
            f.write(f"True Positives (TP):    {self.metrics['true_positives']}\n")
            f.write(f"True Negatives (TN):    {self.metrics['true_negatives']}\n")
            f.write(f"False Positives (FP):   {self.metrics['false_positives']}\n")
            f.write(f"False Negatives (FN):   {self.metrics['false_negatives']}\n")
            
            f.write("\n\nDETAILED CLASSIFICATION REPORT:\n")
            f.write("-" * 70 + "\n")
            f.write(classification_report(self.y_true, self.y_pred, 
                                         target_names=['Safe (0)', 'SQL Injection (1)']))
            
            f.write("\n" + "="*70 + "\n")
        
        print(f" Classification report saved: {filepath}")


def run_evaluation():
    """
    Main function to run complete model evaluation
    Usage: python model_evaluator.py
    """
    print("\n Starting SQL Injection Model Evaluation...")
    
    # Load test data
    print(" Loading test dataset...")
    data = pd.read_csv('./dataset/Modified_SQL_Dataset.csv')
    X = data['Query']
    y = data['Label']
    
    # Split data (same as training)
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print(f" Test set loaded: {len(X_test)} samples")
    print(f"   - Safe queries: {sum(y_test == 0)}")
    print(f"   - SQL injection queries: {sum(y_test == 1)}")
    
    # Initialize evaluator
    print("\n Loading trained model and vectorizer...")
    evaluator = SQLInjectionModelEvaluator(
        model_path='./Models/sql_injection_model.pkl',
        vectorizer_path='./Models/vectorizer.pkl'
    )
    
    # Run evaluation
    print("\n Running comprehensive evaluation...\n")
    metrics = evaluator.evaluate_model(X_test, y_test, save_results=True)
    
    print("\n Evaluation complete!")
    print(" Check the 'evaluation_results' folder for all visualizations and reports.")
    
    return metrics


if __name__ == "__main__":
    run_evaluation()