# make_samples_xlsx.py
# Python 2.7 compatible with progress messages + family folder name + file extension

import os
from openpyxl import Workbook

# Paths
GOODWARE_DIR = os.path.expanduser("~/Documents/Goodware")
RANSOMWARE_DIR = os.path.expanduser("~/Documents/Extracted_Malware")

OUT_FILE = "samples.xlsx"

def get_file_extension(filename):
    """Return file extension including dot, e.g., '.exe', or empty string if none."""
    return os.path.splitext(filename)[1]

def main():
    rows = []
    
    # Process Goodware
    print("Processing Goodware samples...")
    goodware_files = sorted(os.listdir(GOODWARE_DIR))
    count_good = 0
    for fname in goodware_files:
        fpath = os.path.join(GOODWARE_DIR, fname)
        if os.path.isfile(fpath):
            ext = get_file_extension(fname)
            rows.append([fname, 0, "Goodware", ext])
            count_good += 1
    print("  Added {} goodware samples".format(count_good))
    
    # Process Ransomware families
    print("Processing Ransomware families...")
    ransomware_families = sorted(os.listdir(RANSOMWARE_DIR))
    family_id = 1
    total_ransomware = 0
    for folder in ransomware_families:
        folder_path = os.path.join(RANSOMWARE_DIR, folder)
        if os.path.isdir(folder_path):
            ransomware_files = sorted(os.listdir(folder_path))
            count_family = 0
            for fname in ransomware_files:
                fpath = os.path.join(folder_path, fname)
                if os.path.isfile(fpath):
                    ext = get_file_extension(fname)  # may be empty
                    rows.append([fname, family_id, folder, ext])
                    count_family += 1
                    total_ransomware += 1
            print("  Family {} ({}): {} samples".format(family_id, folder, count_family))
            family_id += 1
    
    # Write to Excel
    wb = Workbook()
    ws = wb.active
    ws.title = "Samples"
    ws.append(["sample_name/SHA256", "family", "family_name", "file_extension"])  # headers
    
    for row in rows:
        ws.append(row)
    
    wb.save(OUT_FILE)
    print("Saved {} rows total ({} goodware + {} ransomware) to {}".format(
        len(rows), count_good, total_ransomware, OUT_FILE
    ))


if __name__ == "__main__":
    main()

