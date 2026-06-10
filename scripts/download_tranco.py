import urllib.request
import zipfile
import io
import os

URL = "https://tranco-list.eu/top-1m.csv.zip"
OUTPUT_PATH = os.path.join("src", "data", "tranco_top_1m.txt")

def main():
    print(f"Downloading Tranco list from {URL}...")
    req = urllib.request.Request(URL, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req) as response:
        with zipfile.ZipFile(io.BytesIO(response.read())) as z:
            # The zip file contains top-1m.csv
            csv_filename = z.namelist()[0]
            print(f"Extracting {csv_filename}...")
            with z.open(csv_filename) as f:
                lines = f.read().decode('utf-8').splitlines()
                
    print(f"Total domains: {len(lines)}")
    # Extract top 1M
    top_1m = []
    for line in lines:
        parts = line.strip().split(',')
        if len(parts) >= 2:
            top_1m.append(parts[1])
            
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, 'w', encoding='utf-8') as out_f:
        out_f.write("\n".join(top_1m))
        
    print(f"Saved {len(top_1m)} domains to {OUTPUT_PATH}")

if __name__ == "__main__":
    main()
