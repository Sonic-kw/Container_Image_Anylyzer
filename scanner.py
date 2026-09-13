import subprocess
import json
import pandas as pd
import os
import requests
from tqdm import tqdm 

def get_popular_images(limit=100):
    print(f"--- Pobieranie listy {limit} obrazów z Docker Hub ---")
    url = f"https://hub.docker.com/v2/repositories/library/?page_size={limit}"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        return [repo['name'] for repo in data.get('results', [])]
    except Exception as e:
        print(f"Błąd API Docker Hub: {e}.")
        return None

def run_trivy_scan(image_name, output_file):
    command = [
        "trivy", "image",
        # Bez tego Trivy odpytuje najpierw demona hosta i sciaga obrazy
        # do lokalnego storage Dockera.
        "--image-src", "remote",
        "--format", "json",
        "--output", f"/app/reports/{output_file}",
        "--cache-dir", "/app/trivy_cache",
        image_name
    ]
    try:
        subprocess.run(command, check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError as e:
        return False
    
def parse_trivy_report(json_path):
    if not os.path.exists(json_path) or os.path.isdir(json_path):
        return []

    with open(json_path , 'r') as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            return []

    results_list = []
    if 'Results' in data:
        for result in data['Results']:
            target = result.get('Target', 'unknown')
            vulnerabilities = result.get('Vulnerabilities', [])
            
            for v in vulnerabilities:
                results_list.append({
                    'Image': os.path.basename(json_path).replace("report_", "").replace(".json", ""),
                    'Target': target,
                    'CVE_ID': v.get('VulnerabilityID'),
                    'Package': v.get('PkgName'),
                    'Severity': v.get('Severity'),
                    'Installed_Ver': v.get('InstalledVersion'),
                    'Fixed_Ver': v.get('FixedVersion', 'N/A')
                })
    return results_list

def create_summary_report(all_data):
    df = pd.DataFrame(all_data)
    if df.empty:
        print("\nBrak danych do analizy. Sprawdź, czy raporty JSON nie są puste.")
        return

    print("\n" + "="*40)
    print("      STATYSTYKI BEZPIECZEŃSTWA")
    print("="*40)
    
    print("\n[1] Rozkład Severity:")
    print(df['Severity'].value_counts().to_string())

    print("\n[2] Top 10 najbardziej dziurawych pakietów:")
    print(df['Package'].value_counts().head(10).to_string())

    output_path = "/app/final_summary.csv"
    df.to_csv(output_path, index=False)
    print(f"\n[OK] Pełny raport zapisano do: {output_path}")

def main():
    for folder in ["/app/reports", "/app/trivy_cache"]:
        os.makedirs(folder, exist_ok=True)
    
    images = get_popular_images(limit=100) 
    
    print(f"\nRozpoczynam skanowanie/aktualizację {len(images)} obrazów...")

    for img in tqdm(images, desc="Skanowanie"):
        safe_name = img.replace(":", "_").replace("/", "_")
        report_file = f"report_{safe_name}.json"
        run_trivy_scan(img, report_file)
    
    print("\nAnalizowanie wszystkich znalezionych raportów...")
    parsed_list = []
    
    all_json_files = [f for f in os.listdir("/app/reports") if f.endswith('.json')]
    
    if not all_json_files:
        print("Błąd: Folder /app/reports jest pusty!")
        return

    for rep in tqdm(all_json_files, desc="Parsowanie"):
        report_path = os.path.join("/app/reports", rep)
        data = parse_trivy_report(report_path)
        if data:
            parsed_list.extend(data)
    
    create_summary_report(parsed_list)

if __name__ == "__main__":
    main()