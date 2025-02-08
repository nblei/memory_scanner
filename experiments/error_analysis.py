#!/usr/bin/env python3

import subprocess
import tempfile
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
import json
import argparse
from datetime import datetime

ERROR_RATE = 0.001  # Fixed rate for whichever type of error we're injecting


def run_pagerank(seed, with_monitor=False, error_count=0, use_pointer_errors=True):
    """Run pagerank with optional error injection"""
    base_cmd = ["../build/bin/pagerank", str(seed)]
    monitor_cmd = ["./bin/pagerank", "--", str(seed)]

    if with_monitor:
        cmd = [
            "../build/process_monitor",
            "periodic",  # Changed from periodic to once
            "--error-type",
            "bitflip",
            "--pointer-error-rate",
            str(ERROR_RATE if use_pointer_errors else 0.0),
            "--non-pointer-error-rate",
            str(0.0 if use_pointer_errors else ERROR_RATE),
            "--error-limit",
            str(error_count),
        ]
        cmd.extend(monitor_cmd)  # Add program and its args at the end
    else:
        cmd = base_cmd

    print(f"Running command: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        print(f"Return code: {result.returncode}")
        print(f"Output: {result.stdout}")
        if result.returncode != 0:
            print(f"Error output: {result.stderr}")
            return None
        return result.stdout
    except subprocess.TimeoutExpired:
        print("Timeout!")
        return None


def parse_pagerank_output(output):
    """Extract ranked pages from output"""
    if output is None:
        return None

    try:
        lines = output.split("\n")
        pages = []
        reading_pages = False
        for line in lines:
            if "Top 10 pages:" in line:
                reading_pages = True
                continue
            if reading_pages and line.strip():
                if "WARNING" in line:  # Stop if we hit warnings
                    break
                parts = line.split(":")
                if len(parts) == 2:
                    page_id = int(parts[0].split()[1])
                    rank = float(parts[1])
                    pages.append((page_id, rank))
        return pages if pages else None
    except:
        return None


def outputs_match(output1, output2, tolerance=1e-6):
    """Compare two pagerank outputs within tolerance"""
    if output1 is None or output2 is None:
        return False

    if len(output1) != len(output2):
        return False

    for (id1, rank1), (id2, rank2) in zip(output1, output2):
        if id1 != id2 or abs(rank1 - rank2) > tolerance:
            return False
    return True


def run_experiment(seeds, error_counts):
    """Run experiment comparing pointer vs non-pointer errors"""
    results = []
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    for seed in seeds:
        # Get baseline output WITHOUT monitor
        print(f"Getting baseline for seed {seed}")
        baseline = parse_pagerank_output(run_pagerank(seed, with_monitor=False))
        if baseline is None:
            print(f"Failed to get baseline for seed {seed}")
            continue

        print(f"Baseline output: {baseline}")

        # Test both pointer and non-pointer errors
        for use_pointer_errors in [True, False]:
            error_type = "pointer" if use_pointer_errors else "non-pointer"

            for count in error_counts:
                print(
                    f"Running seed={seed} error_count={
                        count} type={error_type}"
                )
                output = parse_pagerank_output(
                    run_pagerank(seed, True, count, use_pointer_errors)
                )
                success = outputs_match(baseline, output) if output else False

                results.append(
                    {
                        "seed": seed,
                        "error_count": count,
                        "error_type": error_type,
                        "success": success,
                        "completed": output is not None,
                    }
                )

    # Convert to DataFrame
    df = pd.DataFrame(results)

    # Save raw data
    output_file = f"error_results_{timestamp}.csv"
    df.to_csv(output_file, index=False)
    print(f"Results saved to {output_file}")

    return df, timestamp


def plot_results(df, timestamp):
    """Create visualizations of results"""
    # Success and completion rates vs number of errors, separated by type
    plt.figure(figsize=(12, 6))

    # Calculate rates for each error type
    for error_type in ["pointer", "non-pointer"]:
        type_df = df[df["error_type"] == error_type]
        success_rates = type_df.groupby("error_count")["success"].mean()
        completion_rates = type_df.groupby("error_count")["completed"].mean()

        plt.plot(
            success_rates.index,
            success_rates.values * 100,
            marker="o",
            label=f"{error_type} Success Rate",
        )
        plt.plot(
            completion_rates.index,
            completion_rates.values * 100,
            marker="s",
            linestyle="--",
            label=f"{error_type} Completion Rate",
        )

    plt.title("Success and Completion Rates by Error Type and Count")
    plt.xlabel("Number of Errors Injected")
    plt.ylabel("Rate (%)")
    plt.legend()
    plt.grid(True)
    plot_file = f"error_comparison_{timestamp}.png"
    plt.savefig(plot_file)
    print(f"Plot saved to {plot_file}")
    plt.close()

    # Box plot comparing distributions
    plt.figure(figsize=(12, 6))
    sns.boxplot(data=df, x="error_count", y="success", hue="error_type")
    plt.title("Distribution of Success Rate by Error Type and Count")
    plt.xlabel("Number of Errors Injected")
    plt.ylabel("Success Rate")
    plot_file = f"error_distribution_{timestamp}.png"
    plt.savefig(plot_file)
    print(f"Distribution plot saved to {plot_file}")
    plt.close()


def main():
    parser = argparse.ArgumentParser(
        description="Run PageRank error injection experiments"
    )
    parser.add_argument(
        "--seeds",
        type=int,
        nargs="+",
        default=[0, 1, 2, 3, 4],
        help="Random seeds to use for PageRank initialization",
    )
    parser.add_argument(
        "--error-counts",
        type=int,
        nargs="+",
        default=[1, 2, 5, 10, 20, 50, 100],
        help="Number of errors to inject (will test both pointer and non-pointer)",
    )
    parser.add_argument(
        "--output", type=str, default="results", help="Base name for output files"
    )
    args = parser.parse_args()

    df, timestamp = run_experiment(args.seeds, args.error_counts)

    plot_results(df, timestamp)


if __name__ == "__main__":
    main()
