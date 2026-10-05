"""
Intel-Protect Machine Learning Model Registry.
Provides safe, cached loading and serving of locally trained model artifacts.
Guarantees that models are loaded from trusted local artifacts only.
"""
import os
import json
import logging
import joblib

logger = logging.getLogger("intel_protect.ml")

ARTIFACTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "artifacts"))

class MLModelRegistry:
    _instance = None
    _models = {}
    _report = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _load_joblib_artifact(self, filename: str):
        path = os.path.join(ARTIFACTS_DIR, filename)
        if filename not in self._models:
            if not os.path.exists(path):
                raise FileNotFoundError(f"ML artifact '{filename}' not found at {path}. Run training first.")
            logger.info(f"Loading ML artifact: {filename}")
            self._models[filename] = joblib.load(path)
        return self._models[filename]

    def get_document_sensitivity_model(self, model_type: str = "rf"):
        """Returns loaded Document Sensitivity Classifier ('rf' or 'logreg')."""
        filename = "sensitivity_rf.joblib" if model_type == "rf" else "sensitivity_logreg.joblib"
        return self._load_joblib_artifact(filename)

    def get_exposure_models(self):
        """Returns (TfidfVectorizer, RandomForestClassifier) for Exposure Analysis."""
        tfidf = self._load_joblib_artifact("tfidf_vectorizer.joblib")
        clf = self._load_joblib_artifact("exposure_classifier.joblib")
        return tfidf, clf

    def get_breach_priority_model(self):
        """Returns loaded Breach Priority Random Forest model."""
        return self._load_joblib_artifact("breach_priority_rf.joblib")

    def get_anomaly_model(self):
        """Returns loaded Isolation Forest Anomaly Detector."""
        return self._load_joblib_artifact("anomaly_iforest.joblib")

    def get_evaluation_report(self) -> dict:
        """Returns parsed evaluation report metrics."""
        if self._report is None:
            path = os.path.join(ARTIFACTS_DIR, "evaluation_report.json")
            if not os.path.exists(path):
                return {"status": "uninitialized", "message": "No evaluation report available yet."}
            with open(path, "r", encoding="utf-8") as f:
                self._report = json.load(f)
        return self._report

    def clear_cache(self):
        """Clears in-memory model cache."""
        self._models.clear()
        self._report = None

# Global helper singleton
registry = MLModelRegistry.get_instance()
