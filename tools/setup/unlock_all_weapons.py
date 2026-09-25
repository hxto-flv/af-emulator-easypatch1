#!/usr/bin/env python3
"""
Helper script to add all available weapons and shop items into assaultfire_mall_state.json
"""
import json
import os
import sys
from pathlib import Path

# Add server directory to path to import V140_SHOP_ITEM_MAP
REPO_ROOT = Path(__file__).resolve().parents[2]
SERVER_DIR = REPO_ROOT / "server"
sys.path.insert(0, str(SERVER_DIR))

from assaultfire_server_v143b import V140_SHOP_ITEM_MAP, V140_COMMODITY_BUNDLES

MALL_STATE_PATH = SERVER_DIR / "assaultfire_mall_state.json"

def main():
    if not MALL_STATE_PATH.is_file():
        print(f"[ERROR] Could not find {MALL_STATE_PATH}")
        return

    with open(MALL_STATE_PATH, "r", encoding="utf-8") as f:
        state = json.load(f)

    inventory = state.get("inventory", [])
    next_gid = state.get("next_gid", 42953967927307)

    existing_item_ids = {item["item_id"] for item in inventory}

    # Collect all item IDs from shop map and bundles
    all_item_ids = set()
    for comm_id, item_id in V140_SHOP_ITEM_MAP.items():
        all_item_ids.add(item_id)
        if comm_id in V140_COMMODITY_BUNDLES:
            all_item_ids.update(V140_COMMODITY_BUNDLES[comm_id])

    added_count = 0
    for item_id in sorted(all_item_ids):
        if item_id in existing_item_ids:
            continue

        new_prop = {
            "avail_hours": 87600,
            "durability": 100,
            "durability_max": 100,
            "gain_type": 1,
            "gid": next_gid,
            "item_id": item_id,
            "location": 12, # Inventory / Bag location
            "owner_gid": 0,
            "validity": 87600
        }
        inventory.append(new_prop)
        next_gid += 1
        added_count += 1

    state["inventory"] = inventory
    state["next_gid"] = next_gid

    with open(MALL_STATE_PATH, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)

    print(f"[SUCCESS] Added {added_count} new weapons/items to assaultfire_mall_state.json!")
    print(f"[INFO] Total inventory count: {len(inventory)} items.")
    print("[NOTE] Restart assaultfire_server_v143b.py for changes to take effect in game.")

if __name__ == "__main__":
    main()
