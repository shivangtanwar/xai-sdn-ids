"""Loads the trained classifier bundle and scores feature vectors."""
import os

import joblib
import numpy as np

from ids.config import MODEL_PATH


class Detector:
    def __init__(self, path=MODEL_PATH):
        if not os.path.exists(path):
            raise FileNotFoundError(f"model not found: {path} (run ml/train.py first)")
        bundle = joblib.load(path)
        self.model = bundle["model"]
        # One window at a time: a parallel thread pool per call costs far more than it saves.
        if hasattr(self.model, "n_jobs"):
            self.model.n_jobs = 1
        self.features = bundle["features"]
        self.classes = list(self.model.classes_)

    def vectorize(self, feats):
        return np.array([[feats[f] for f in self.features]], dtype=float)

    def predict(self, feats):
        """Returns (label, probability, probability-by-class, feature vector)."""
        x = self.vectorize(feats)
        proba = self.model.predict_proba(x)[0]
        idx = int(np.argmax(proba))
        return self.classes[idx], float(proba[idx]), dict(zip(self.classes, map(float, proba))), x
