#!/usr/bin/env python3
"""Train and compare IDS classifiers, save the deployed model, and produce SHAP figures.

Training and test sets are separate Mininet sessions (different seeds), so the reported
numbers measure generalisation to unseen traffic, not memorised windows.

    python3 ml/train.py --train train1 --test test1
"""
import argparse
import json
import os
import sys
import time

import joblib
import numpy as np
import pandas as pd
import shap
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.neighbors import KNeighborsClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ids.config import CLASSES, FEATURES, MODEL_PATH, ROOT  # noqa: E402
from ml.plotstyle import BLUE_SEQ, INK, SURFACE, hbar, plt  # noqa: E402

RESULTS = os.path.join(ROOT, "results")


def load(runs):
    return pd.concat([pd.read_csv(os.path.join(ROOT, "data", "processed", f"{r}.csv")) for r in runs],
                     ignore_index=True)


def models():
    return {
        "RandomForest": RandomForestClassifier(n_estimators=150, max_depth=14, min_samples_leaf=2,
                                               class_weight="balanced", n_jobs=-1, random_state=42),
        "ExtraTrees": ExtraTreesClassifier(n_estimators=150, max_depth=14, class_weight="balanced",
                                           n_jobs=-1, random_state=42),
        "HistGradientBoosting": HistGradientBoostingClassifier(max_iter=200, class_weight="balanced",
                                                               random_state=42),
        "DecisionTree": DecisionTreeClassifier(max_depth=10, class_weight="balanced", random_state=42),
        "LogisticRegression": make_pipeline(StandardScaler(), LogisticRegression(
            max_iter=2000, class_weight="balanced")),
        "KNN": make_pipeline(StandardScaler(), KNeighborsClassifier(n_neighbors=7)),
        "MLP": make_pipeline(StandardScaler(), MLPClassifier(hidden_layer_sizes=(64, 32), max_iter=600,
                                                             random_state=42)),
    }


def ids_metrics(y_true, y_pred):
    """Multi-class metrics + binary attack-vs-benign FPR/FNR (the IDS view)."""
    acc = accuracy_score(y_true, y_pred)
    p, r, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="macro", zero_division=0)
    benign_t, benign_p = (y_true == "benign"), (y_pred == "benign")
    fpr = (benign_t & ~benign_p).sum() / max(benign_t.sum(), 1)
    fnr = (~benign_t & benign_p).sum() / max((~benign_t).sum(), 1)
    return {"accuracy": acc, "precision": p, "recall": r, "f1": f1, "fpr": fpr, "fnr": fnr}


def plot_confusion(y_true, y_pred, path, title):
    labels = [c for c in CLASSES if c in set(y_true) | set(y_pred)]
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    norm = cm / cm.sum(axis=1, keepdims=True).clip(min=1)
    fig, ax = plt.subplots(figsize=(5.6, 4.6))
    ax.imshow(norm, cmap=BLUE_SEQ, vmin=0, vmax=1)
    ax.grid(False)
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=30, ha="right")
    ax.set_yticks(range(len(labels)))
    ax.set_yticklabels(labels)
    for i in range(len(labels)):
        for j in range(len(labels)):
            ax.text(j, i, f"{norm[i, j]:.2f}\n({cm[i, j]})", ha="center", va="center", fontsize=8,
                    color=SURFACE if norm[i, j] > 0.55 else INK)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title(title)
    fig.savefig(path)
    plt.close(fig)


def shap_figures(model, X_test, y_pred):
    explainer = shap.TreeExplainer(model)
    sample = X_test.sample(min(len(X_test), 600), random_state=0)
    sv = explainer.shap_values(sample)
    sv = np.stack(sv, axis=-1) if isinstance(sv, list) else np.asarray(sv)   # (n, f, classes)
    classes = list(model.classes_)

    # Global importance: mean |SHAP| over samples and classes
    glob = np.abs(sv).mean(axis=(0, 2))
    order = np.argsort(-glob)
    fig, ax = plt.subplots(figsize=(6, 4.6))
    hbar(ax, [FEATURES[i] for i in order], glob[order])
    ax.set_xlabel("mean |SHAP value| (all classes)")
    ax.set_title("Global feature importance (TreeSHAP, RandomForest)")
    fig.savefig(os.path.join(RESULTS, "shap_global_importance.png"))
    plt.close(fig)

    # Per-attack-class importance as small multiples (one hue, comparable layout)
    attack_classes = [c for c in classes if c != "benign"]
    fig, axes = plt.subplots(1, len(attack_classes), figsize=(3.3 * len(attack_classes), 3.6))
    per_class = {}
    for ax, c in zip(np.atleast_1d(axes), attack_classes):
        imp = np.abs(sv[:, :, classes.index(c)]).mean(axis=0)
        top = np.argsort(-imp)[:6]
        per_class[c] = {FEATURES[i]: float(imp[i]) for i in top}
        hbar(ax, [FEATURES[i] for i in top], imp[top], fmt="{:.2f}")
        ax.set_title(c)
        ax.tick_params(axis="y", labelsize=8)
    fig.suptitle("Top features per attack class (mean |SHAP|)", x=0.01, ha="left", fontweight="bold")
    fig.tight_layout()
    fig.savefig(os.path.join(RESULTS, "shap_per_class.png"))
    plt.close(fig)

    # Standard SHAP beeswarm for the class that is hardest to separate (port_scan)
    if "port_scan" in classes:
        plt.figure()
        shap.summary_plot(sv[:, :, classes.index("port_scan")], sample, show=False, max_display=10)
        plt.title("SHAP beeswarm: port_scan")
        plt.savefig(os.path.join(RESULTS, "shap_beeswarm_port_scan.png"))
        plt.close("all")
    return per_class


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", nargs="+", default=["train1"])
    ap.add_argument("--test", nargs="+", default=["test1"])
    args = ap.parse_args()
    os.makedirs(RESULTS, exist_ok=True)
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)

    train, test = load(args.train), load(args.test)
    X_tr, y_tr = train[FEATURES], train["label"].values
    X_te, y_te = test[FEATURES], test["label"].values
    print("train:", dict(pd.Series(y_tr).value_counts()), "\ntest:", dict(pd.Series(y_te).value_counts()))

    rows, fitted = [], {}
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    for name, model in models().items():
        cv_f1 = cross_val_score(model, X_tr, y_tr, cv=cv, scoring="f1_macro", n_jobs=1).mean()
        t0 = time.perf_counter()
        model.fit(X_tr, y_tr)
        fit_s = time.perf_counter() - t0
        t0 = time.perf_counter()
        y_hat = model.predict(X_te)
        infer_us = (time.perf_counter() - t0) / len(X_te) * 1e6
        m = ids_metrics(y_te, y_hat)
        rows.append({"model": name, "cv_f1_macro": cv_f1, **m, "train_s": fit_s, "infer_us_per_sample": infer_us})
        fitted[name] = (model, y_hat)
        print(f"{name:22s} cvF1={cv_f1:.3f} acc={m['accuracy']:.3f} F1={m['f1']:.3f} "
              f"FPR={m['fpr']:.3f} FNR={m['fnr']:.3f}")

    table = pd.DataFrame(rows).sort_values("f1", ascending=False)
    table.to_csv(os.path.join(RESULTS, "model_comparison.csv"), index=False, float_format="%.4f")

    fig, ax = plt.subplots(figsize=(6, 3.8))
    hbar(ax, list(table["model"]), list(table["f1"]))
    ax.set_xlabel("Macro F1 on held-out session")
    ax.set_title("Model comparison (5 classes)")
    fig.savefig(os.path.join(RESULTS, "model_comparison_f1.png"))
    plt.close(fig)

    # Deployed model: RandomForest (accurate, fast, exact TreeSHAP)
    rf, rf_pred = fitted["RandomForest"]
    plot_confusion(y_te, rf_pred, os.path.join(RESULTS, "confusion_matrix_rf.png"),
                   "RandomForest confusion matrix (held-out session)")
    p, r, f1, sup = precision_recall_fscore_support(y_te, rf_pred, labels=CLASSES, zero_division=0)
    per_class = pd.DataFrame({"class": CLASSES, "precision": p, "recall": r, "f1": f1, "support": sup})
    per_class.to_csv(os.path.join(RESULTS, "rf_per_class.csv"), index=False, float_format="%.4f")
    print(per_class.to_string(index=False))

    signatures = shap_figures(rf, X_te, rf_pred)
    with open(os.path.join(RESULTS, "shap_class_signatures.json"), "w") as f:
        json.dump(signatures, f, indent=2)
    joblib.dump({"model": rf, "features": FEATURES, "trained_on": args.train}, MODEL_PATH)
    print("saved", MODEL_PATH)


if __name__ == "__main__":
    main()
