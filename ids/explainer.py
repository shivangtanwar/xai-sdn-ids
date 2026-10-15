"""Feature-level explanations of individual predictions using SHAP (TreeExplainer)."""
import numpy as np
import shap


class Explainer:
    def __init__(self, detector):
        self.detector = detector
        self.explainer = shap.TreeExplainer(detector.model)

    def class_shap(self, x, label):
        """SHAP values (one per feature) for the given class, for a single sample x."""
        values = self.explainer.shap_values(x)
        ci = self.detector.classes.index(label)
        if isinstance(values, list):          # older shap: list[class] of (n, features)
            return np.asarray(values[ci])[0]
        values = np.asarray(values)           # newer shap: (n, features, classes)
        return values[0, :, ci]

    def explain(self, x, label, top_k=3):
        """Top-k features pushing the prediction towards `label`, largest first."""
        sv = self.class_shap(x, label)
        order = np.argsort(-sv)
        names = self.detector.features
        return [
            {"feature": names[i], "value": float(x[0, i]), "shap": float(sv[i])}
            for i in order[:top_k]
        ]
