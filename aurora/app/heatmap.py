from __future__ import annotations

from typing import List

import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

from aurora.models.risk_schema import DomainRiskResult


def plot_risk_heatmap(domain_results: List[DomainRiskResult]):
    data = {
        "domain": [r.domain.value for r in domain_results],
        "score": [r.score_0_100 for r in domain_results],
        "confidence": [r.confidence_0_1 for r in domain_results],
    }
    df = pd.DataFrame(data)
    df = df.sort_values("score", ascending=False)

    pivot = df.set_index("domain")[["score"]]

    plt.figure(figsize=(8, max(2.8, 0.55 * len(pivot))))
    ax = sns.heatmap(
        pivot,
        annot=True,
        fmt=".0f",
        cmap="Reds",
        vmin=0,
        vmax=100,
        cbar=True,
        linewidths=0.4,
        linecolor="#f0f0f0",
    )
    ax.set_title("AURORA Risk Heatmap (0–100)")
    ax.set_xlabel("")
    ax.set_ylabel("")
    plt.tight_layout()

    return plt.gcf()
