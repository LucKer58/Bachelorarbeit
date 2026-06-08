#!/usr/bin/env python3
"""Aggregate + visualize the evaluation CSVs (hijack success and convergence).

Reads the two experiment CSVs, prints summary tables (mean +/- std across runs), and
writes a set of figures for the thesis. Hijack-success data comes from
run_random_experiments.py (results/random_runs.csv); convergence data from
run_convergence_batch.py (results/convergence_runs.csv, optional).

This is an *analysis* script and deliberately separate from the testbed runtime: it is
the only part of the project that needs pandas/matplotlib/seaborn
(see requirements-analysis.txt). Install with:
    pip install -r requirements-analysis.txt

Usage:
    python3 scripts/aggregate_results.py
    python3 scripts/aggregate_results.py --format pdf      # vector figures for LaTeX
"""
import argparse
import os
import sys

try:
    import pandas as pd
    import matplotlib
    matplotlib.use("Agg")  # headless: write files, never open a window
    import matplotlib.pyplot as plt
    import seaborn as sns
except ImportError as exc:  # pragma: no cover
    sys.stderr.write(
        f"Missing analysis dependency ({exc}).\n"
        "Install with: pip install -r requirements-analysis.txt\n"
    )
    raise SystemExit(1)

# Catalog order + human-readable labels. Each label states the prefix specificity
# (subprefix vs. exact) and the technique, so the attack/defense type is explicit on
# every axis. Origin-code manipulation is intentionally EXCLUDED: it is not a viable
# hijack vector (origin is a late BGP tiebreaker and both routes are already IGP, so the
# censor cannot win -- an effect only appears if a legit AS degrades its own route).
# Order groups attacks first (reach) then defenses (effect, vs. the exact-hijack
# baseline), so the heatmap/distribution read as two blocks. DEFENSE_IDS marks the
# defenses so the heatmap can draw the attack/defense separator line.
DEFENSE_IDS = {"3_exact_hijack_with_pref", "4_exact_hijack_with_defense", "6_rpki_test"}
ATTACK_ORDER = [
    # attacks (reach)
    "1_subprefix_hijack", "2_exact_hijack_no_pref", "5_path_poisoning",
    "8_path_forgery", "7_origin_spoofing_rpki", "9_mitm_attack",
    # defenses (effect)
    "3_exact_hijack_with_pref", "4_exact_hijack_with_defense", "6_rpki_test",
]
ATTACK_LABELS = {
    "1_subprefix_hijack": "Subprefix hijack",
    "2_exact_hijack_no_pref": "Exact-prefix hijack",
    "3_exact_hijack_with_pref": "Exact + local-pref",
    "4_exact_hijack_with_defense": "Exact + AS-path prepend",
    "5_path_poisoning": "Subprefix + AS-path poison",
    "6_rpki_test": "Exact + RPKI",
    "7_origin_spoofing_rpki": "Exact + origin spoofing",
    "8_path_forgery": "Exact + AS-path forgery",
    "9_mitm_attack": "Subprefix + MITM",
}

# Focused trend-by-tier comparisons, in narrative order. The FIRST id in each list is
# the reference (drawn grey); every other line reads as a delta from it, so each figure
# isolates exactly one variable: prefix length, a single technique, or a single defense.
COMPARISONS = {
    "exact_vs_subprefix": (
        "Exact-prefix vs. subprefix hijack",
        ["2_exact_hijack_no_pref", "1_subprefix_hijack"],
    ),
    "subprefix_vs_poisoning": (
        "Subprefix hijack vs. AS-path poisoning",
        ["1_subprefix_hijack", "5_path_poisoning"],
    ),
    "path_manipulation": (
        "Exact-prefix vs. AS-path forgery vs. origin spoofing",
        ["2_exact_hijack_no_pref", "8_path_forgery", "7_origin_spoofing_rpki"],
    ),
    "defenses": (
        "Exact-prefix vs. local-pref vs. AS-path prepend vs. RPKI",
        ["2_exact_hijack_no_pref", "3_exact_hijack_with_pref",
         "4_exact_hijack_with_defense", "6_rpki_test"],
    ),
    "rpki_evasion": (
        "RPKI vs. origin spoofing",
        ["6_rpki_test", "7_origin_spoofing_rpki"],
    ),
}


# Tier colours (tab10 reordered): Tier 1 = orange, Tier 2 = green, Tier 3 = blue.
_TAB10 = sns.color_palette("tab10")
TIER_PALETTE = {"Tier 1": _TAB10[1], "Tier 2": _TAB10[2], "Tier 3": _TAB10[0]}


def load_hijack(path: str):
    if not os.path.exists(path):
        return None
    df = pd.read_csv(path)
    df["hijack_rate"] = pd.to_numeric(df.get("hijack_rate"), errors="coerce")
    df["tier"] = pd.to_numeric(df.get("tier"), errors="coerce")
    df = df.dropna(subset=["hijack_rate", "tier", "scenario"])
    # Curated attack set only (drops e.g. origin-code manipulation, not in ATTACK_ORDER).
    df = df[df["scenario"].isin(ATTACK_ORDER)].copy()
    df["tier"] = df["tier"].astype(int)
    df["attack"] = pd.Categorical(
        df["scenario"].map(lambda s: ATTACK_LABELS.get(s, s)),
        categories=[ATTACK_LABELS.get(s, s) for s in ATTACK_ORDER],
        ordered=True,
    )
    return df


def load_convergence(path: str):
    if not os.path.exists(path):
        return None
    df = pd.read_csv(path)
    for col in ("decensor_net_s", "ping_net_s", "tier"):
        if col in df:
            df[col] = pd.to_numeric(df[col], errors="coerce")
    df = df.dropna(subset=["tier", "mode"])
    df["tier"] = df["tier"].astype(int)
    return df


def save_fig(fig, outdir: str, name: str, fmt: str, dpi: int) -> None:
    path = os.path.join(outdir, f"{name}.{fmt}")
    fig.tight_layout()
    fig.savefig(path, dpi=dpi, bbox_inches="tight")
    plt.close(fig)
    print(f"  wrote {path}")


def _rotate(ax) -> None:
    plt.setp(ax.get_xticklabels(), rotation=30, ha="right")


# --------------------------------------------------------------------------- #
# Tables
# --------------------------------------------------------------------------- #
def print_hijack_tables(df, outdir: str) -> None:
    print("\n=== Hijack success: mean hijack_rate (%) by attack x tier ===")
    pivot = df.pivot_table(
        index="scenario", columns="tier", values="hijack_rate", aggfunc="mean"
    ).reindex(ATTACK_ORDER)
    pivot["mean"] = df.groupby("scenario")["hijack_rate"].mean().reindex(ATTACK_ORDER)
    print(pivot.round(1).to_string())
    pivot.round(2).to_csv(os.path.join(outdir, "table_hijack_by_attack_tier.csv"))

    runs = df["run"].nunique() if "run" in df else "?"
    print(f"\n(std across {runs} runs)")
    std = df.pivot_table(index="scenario", columns="tier", values="hijack_rate", aggfunc="std")
    print(std.reindex(ATTACK_ORDER).round(1).to_string())


def print_convergence_tables(df, outdir: str) -> None:
    print("\n=== Convergence: mean de-hijack recovery (s) by tier x mode ===")
    pivot = df.pivot_table(index="tier", columns="mode", values="decensor_net_s", aggfunc="mean")
    print(pivot.round(3).to_string())
    pivot.round(4).to_csv(os.path.join(outdir, "table_convergence_by_tier_mode.csv"))
    if {"graceful", "stop"}.issubset(pivot.columns):
        cost = (pivot["stop"] - pivot["graceful"]).round(3)
        print("\nDetection cost (stop - graceful), per tier:")
        print(cost.to_string())


# --------------------------------------------------------------------------- #
# Figures
# --------------------------------------------------------------------------- #
def plot_hijack(df, outdir: str, fmt: str, dpi: int) -> None:
    # 1. Overview: attack x tier heatmap of mean hijack rate (every attack at a glance).
    pivot = df.pivot_table(index="scenario", columns="tier", values="hijack_rate",
                           aggfunc="mean").reindex(ATTACK_ORDER)
    pivot.index = [ATTACK_LABELS.get(s, s) for s in pivot.index]
    fig, ax = plt.subplots(figsize=(6, 6))
    sns.heatmap(pivot, annot=True, fmt=".0f", cmap="Reds", vmin=0, vmax=100,
                cbar_kws={"label": "Hijack rate (%)"}, ax=ax)
    n_attacks = sum(1 for s in ATTACK_ORDER if s not in DEFENSE_IDS)
    ax.axhline(n_attacks, color="white", linewidth=4)  # attacks (above) vs. defenses (below)
    ax.set(xlabel="Attacker tier", ylabel="",
           title="Mean hijack rate (%): attacks (top) vs. defenses (bottom)")
    save_fig(fig, outdir, "hijack_heatmap", fmt, dpi)

    # 2. Run-to-run variation, one panel per tier. Each box = spread of an attack's
    #    hijack rate across the runs at that tier (how reproducible the result is).
    tiers = sorted(df["tier"].unique())
    fig, axes = plt.subplots(1, len(tiers), figsize=(6 * len(tiers), 5), sharey=True)
    if len(tiers) == 1:
        axes = [axes]
    for ax, t in zip(axes, tiers):
        sub = df[df["tier"] == t].copy()
        sub["attack"] = sub["attack"].cat.remove_unused_categories()
        sns.boxplot(data=sub, x="attack", y="hijack_rate", color="0.85", ax=ax)
        sns.stripplot(data=sub, x="attack", y="hijack_rate", color="0.25",
                      alpha=0.6, ax=ax)
        ax.set(xlabel="", title=f"Tier {t}")
        ax.set_ylabel("Hijack rate (%)" if ax is axes[0] else "")
        _rotate(ax)
    fig.suptitle("Hijack-rate distribution across runs, per attacker tier")
    save_fig(fig, outdir, "hijack_distribution_by_tier", fmt, dpi)


def plot_comparisons(df, outdir: str, fmt: str, dpi: int) -> None:
    """Focused trend-by-tier comparisons (hijack reach vs. attacker tier).

    The first scenario in each COMPARISONS list is the reference, drawn grey; every
    other line reads as a delta from it, so each figure isolates one variable.
    """
    for name, (title, ids) in COMPARISONS.items():
        sub = df[df["scenario"].isin(ids)].copy()
        if sub.empty:
            continue
        sub["attack"] = sub["attack"].cat.remove_unused_categories()
        present = set(sub["attack"].dropna().unique())
        order = [lbl for lbl in (ATTACK_LABELS.get(s, s) for s in ids) if lbl in present]
        if not order:
            continue

        # First entry = reference in grey, the rest from a categorical cycle.
        ref_label, others = order[0], order[1:]
        palette = {ref_label: "0.6"}
        palette.update(dict(zip(others, sns.color_palette("tab10", len(others)))))

        fig, ax = plt.subplots(figsize=(7, 5))
        sns.pointplot(data=sub, x="tier", y="hijack_rate", hue="attack", hue_order=order,
                      palette=palette, errorbar=("ci", 95), seed=0, dodge=0.2, ax=ax)
        ax.set(xlabel="Attacker tier (1 = core, 3 = edge)", ylabel="Hijack rate (%)",
               title=title, ylim=(0, 105))
        ax.legend(title="Attack (grey = reference)", fontsize=8)
        save_fig(fig, outdir, name, fmt, dpi)


def plot_convergence(df, outdir: str, fmt: str, dpi: int) -> None:
    # Recovery time by attacker tier, graceful vs. stop withdrawal. The gap between the
    # two modes is the cost of *detecting* a dead session before reconverging.
    # (Control- vs. data-plane is deliberately not plotted: in this setup the two
    # planes recover together, so the figure would be two identical bars -- note it in
    # the text instead.)
    fig, ax = plt.subplots(figsize=(7, 5))
    sns.barplot(data=df, x="tier", y="decensor_net_s", hue="mode", errorbar=("ci", 95),
                seed=0, ax=ax)
    ax.set(xlabel="Attacker tier", ylabel="De-hijack recovery (s)",
           title="Convergence time by attacker tier and withdrawal mode")
    ax.legend(title="Withdrawal mode")
    save_fig(fig, outdir, "convergence_by_tier_mode", fmt, dpi)


def load_coalition(path: str):
    if not os.path.exists(path):
        return None
    df = pd.read_csv(path)
    for col in ("k", "tier", "hijack_rate"):
        df[col] = pd.to_numeric(df.get(col), errors="coerce")
    df = df.dropna(subset=["k", "tier", "hijack_rate"])
    df["k"] = df["k"].astype(int)
    df["tier_label"] = "Tier " + df["tier"].astype(int).astype(str)
    return df


def load_rpki_sweep(path: str):
    if not os.path.exists(path):
        return None
    df = pd.read_csv(path)
    for col in ("m", "attacker_tier", "true_hijack_rate", "hijack_rate"):
        if col in df:
            df[col] = pd.to_numeric(df[col], errors="coerce")
    df = df.dropna(subset=["m", "attacker_tier", "true_hijack_rate"])
    df["m"] = df["m"].astype(int)
    df["tier_label"] = "Tier " + df["attacker_tier"].astype(int).astype(str)
    return df


def plot_coalition(df, outdir: str, fmt: str, dpi: int) -> None:
    # Hijack reach as the attacker coalition grows: one line per attacker tier, 95% CI
    # across runs. The dashed line marks full capture (100%). Note the denominator shrinks
    # with k (censors are not sources), so 100% = all remaining non-censor ASes.
    fig, ax = plt.subplots(figsize=(8, 5))
    sns.lineplot(data=df, x="k", y="hijack_rate", hue="tier_label", marker="o",
                 errorbar=("ci", 95), seed=0, palette=TIER_PALETTE, ax=ax)
    ax.axhline(100, color="0.5", linestyle="--", linewidth=0.8)
    ax.set(xlabel="Number of colluding censors (k)", ylabel="Hijack rate (%)",
           title="Attacker coalition: hijack reach vs. number of censors (exact prefix)",
           ylim=(0, 105))
    ax.set_xticks(sorted(df["k"].unique()))
    ax.legend(title="Attacker tier")
    save_fig(fig, outdir, "coalition_curve", fmt, dpi)


def plot_rpki_sweep(df, outdir: str, fmt: str, dpi: int) -> None:
    # True hijack rate (sources actually using the /25) as RPKI/ROV is deployed core-first:
    # one line per attacker tier, 95% CI across runs. The dashed line marks "useless" (0%).
    fig, ax = plt.subplots(figsize=(8, 5))
    sns.lineplot(data=df, x="m", y="true_hijack_rate", hue="tier_label", marker="o",
                 errorbar=("ci", 95), seed=0, palette=TIER_PALETTE, ax=ax)
    ax.axhline(0, color="0.5", linestyle="--", linewidth=0.8)
    ax.set(xlabel="Number of RPKI/ROV routers (core-first deployment)",
           ylabel="True hijack rate (%)",
           title="RPKI deployment threshold: sub-prefix hijack neutralized",
           ylim=(-2, 105))
    ax.set_xticks(sorted(df["m"].unique()))
    ax.legend(title="Attacker tier")
    save_fig(fig, outdir, "rpki_sweep_curve", fmt, dpi)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--hijack-csv", default=os.path.join("results", "random_runs.csv"))
    parser.add_argument("--convergence-csv", default=os.path.join("results", "convergence_runs.csv"))
    parser.add_argument("--coalition-csv", default=os.path.join("results", "coalition.csv"))
    parser.add_argument("--rpki-sweep-csv", default=os.path.join("results", "rpki_sweep.csv"))
    parser.add_argument("--outdir", default=os.path.join("results", "plots"))
    parser.add_argument("--format", choices=["png", "pdf"], default="png",
                        help="Figure format (pdf = vector, best for LaTeX).")
    parser.add_argument("--dpi", type=int, default=150)
    args = parser.parse_args()

    sns.set_theme(style="whitegrid", context="paper")
    os.makedirs(args.outdir, exist_ok=True)

    hijack = load_hijack(args.hijack_csv)
    convergence = load_convergence(args.convergence_csv)
    coalition = load_coalition(args.coalition_csv)
    rpki_sweep = load_rpki_sweep(args.rpki_sweep_csv)

    if all(x is None for x in (hijack, convergence, coalition, rpki_sweep)):
        print("No input CSVs found.")
        return 1

    print(f"Writing tables + {args.format} figures to {args.outdir}/")

    if hijack is not None:
        print_hijack_tables(hijack, args.outdir)
        plot_hijack(hijack, args.outdir, args.format, args.dpi)
        plot_comparisons(hijack, args.outdir, args.format, args.dpi)
    else:
        print(f"\n(skipping hijack analysis: {args.hijack_csv} not found)")

    if convergence is not None:
        print_convergence_tables(convergence, args.outdir)
        plot_convergence(convergence, args.outdir, args.format, args.dpi)
    else:
        print(f"\n(skipping convergence analysis: {args.convergence_csv} not found "
              "-- run scripts/run_convergence_batch.py first)")

    if coalition is not None:
        plot_coalition(coalition, args.outdir, args.format, args.dpi)
    if rpki_sweep is not None:
        plot_rpki_sweep(rpki_sweep, args.outdir, args.format, args.dpi)

    print("\nDone.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
