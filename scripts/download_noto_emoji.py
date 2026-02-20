"""
Download all Google Noto Animated Emoji as Lottie JSON files.
License: Apache 2.0 — free to bundle in commercial apps.
Source: https://googlefonts.github.io/noto-emoji-animation/
"""

import requests
import os
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

# Output directory
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "assets", "reactions", "noto")

# Google's emoji data endpoint
DATA_URL = "https://googlefonts.github.io/noto-emoji-animation/data/api.json"

# Base URL for downloading individual animations
BASE_URL = "https://fonts.gstatic.com/s/e/notoemoji/latest"


def download_one(emoji, index, total):
    """Download a single emoji animation."""
    codepoint = emoji["codepoint"]
    name = emoji["name"]
    tags = emoji.get("tags", [])
    tag = tags[0] if tags else name

    # Use codepoint as filename for consistency, tag for human readability
    filename = f"{codepoint}_{tag.strip(':').replace('-', '_')}.json"
    filepath = os.path.join(OUTPUT_DIR, filename)

    if os.path.exists(filepath):
        return "skipped", name, 0

    # Download URL: https://fonts.gstatic.com/s/e/notoemoji/latest/{codepoint}/lottie.json
    url = f"{BASE_URL}/{codepoint}/lottie.json"

    try:
        r = requests.get(url, timeout=20)
        if r.status_code == 200:
            with open(filepath, 'wb') as f:
                f.write(r.content)
            size_kb = len(r.content) / 1024
            return "ok", f"{tag} ({size_kb:.1f}KB)", size_kb
        else:
            # Some multi-codepoint emoji use underscore-separated format
            # e.g., "1f9d1_200d_1f3a8" for artist
            url2 = f"{BASE_URL}/{codepoint.replace(' ', '_')}/lottie.json"
            r2 = requests.get(url2, timeout=20)
            if r2.status_code == 200:
                with open(filepath, 'wb') as f:
                    f.write(r2.content)
                size_kb = len(r2.content) / 1024
                return "ok", f"{tag} ({size_kb:.1f}KB)", size_kb
            return "failed", f"{name} HTTP {r.status_code}", 0
    except Exception as e:
        return "error", f"{name}: {e}", 0


def download_all():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("Fetching emoji list from Google...")
    response = requests.get(DATA_URL)
    if response.status_code != 200:
        print(f"Failed to fetch emoji list: {response.status_code}")
        return

    data = response.json()
    emojis = data["icons"]
    total = len(emojis)
    print(f"Found {total} animated emoji to download")
    print(f"Output: {OUTPUT_DIR}\n")

    # Save metadata for later use in app
    meta_path = os.path.join(OUTPUT_DIR, "_metadata.json")
    with open(meta_path, 'w') as f:
        json.dump(emojis, f)
    print(f"Saved metadata to _metadata.json\n")

    downloaded = 0
    skipped = 0
    failed = 0
    total_size = 0

    # Download with 10 concurrent threads
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(download_one, emoji, i, total): (i, emoji)
            for i, emoji in enumerate(emojis)
        }

        for future in as_completed(futures):
            i, emoji = futures[future]
            status, msg, size = future.result()
            if status == "ok":
                downloaded += 1
                total_size += size
                if downloaded % 25 == 0 or downloaded <= 5:
                    print(f"  [{downloaded}/{total}] {msg}")
            elif status == "skipped":
                skipped += 1
            else:
                failed += 1
                if failed <= 10:
                    print(f"  FAIL: {msg}")

    print(f"\n{'='*50}")
    print(f"Downloaded: {downloaded}")
    print(f"Skipped (existing): {skipped}")
    print(f"Failed: {failed}")
    print(f"Total size: {total_size/1024:.1f} MB")
    print(f"Location: {OUTPUT_DIR}")

    # Save category index for the app
    categories = {}
    for emoji in emojis:
        for cat in emoji.get("categories", ["Other"]):
            if cat not in categories:
                categories[cat] = []
            categories[cat].append({
                "codepoint": emoji["codepoint"],
                "name": emoji["name"],
                "tags": emoji.get("tags", []),
                "popularity": emoji.get("popularity", 0)
            })

    cat_path = os.path.join(OUTPUT_DIR, "_categories.json")
    with open(cat_path, 'w') as f:
        json.dump(categories, f, indent=2)
    print(f"Saved category index: {len(categories)} categories")
    for cat, items in sorted(categories.items()):
        print(f"  {cat}: {len(items)} emoji")


if __name__ == "__main__":
    download_all()
