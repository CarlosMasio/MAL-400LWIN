import json
import csv
import os
from datetime import datetime
from rich import print

def get_timestamp():
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

def save_as_json(report_data, output_dir="reports"):
    os.makedirs(output_dir, exist_ok=True)
    filename = f"scan_report_{get_timestamp()}.json"
    filepath = os.path.join(output_dir, filename)
    
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=4)
    
    print(f"[green]✅ JSON report saved to:[/green] {filepath}")
    return filepath

def save_as_csv(report_data, output_dir="reports"):
    os.makedirs(output_dir, exist_ok=True)
    filename = f"scan_report_{get_timestamp()}.csv"
    filepath = os.path.join(output_dir, filename)
    
    # Flatten basic fields
    with open(filepath, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        
        # Write general file info
        writer.writerow(["Section", "Key", "Value"])
        for section in ['Hashes', 'Metadata', 'YARA Hits', 'IOCs']:
            section_data = report_data.get(section, {})
            if isinstance(section_data, dict):
                for key, value in section_data.items():
                    writer.writerow([section, key, value])
            elif isinstance(section_data, list):
                for item in section_data:
                    writer.writerow([section, "", item])
        
        # If VirusTotal included
        vt = report_data.get("VirusTotal")
        if vt:
            for key, value in vt.items():
                writer.writerow(["VirusTotal", key, value])

        # Write extracted file results if available
        extracted = report_data.get("ExtractedFiles", [])
        if extracted:
            for file_entry in extracted:
                writer.writerow(["ExtractedFile", "Path", file_entry.get("Path", "")])
                for key, value in file_entry.get("Hashes", {}).items():
                    writer.writerow(["ExtractedFile::Hashes", key, value])
                for hit in file_entry.get("YARA Hits", []):
                    writer.writerow(["ExtractedFile::YARA", "", hit])
                for k, v in file_entry.get("IOCs", {}).items():
                    writer.writerow(["ExtractedFile::IOCs", k, v])

    print(f"[green]✅ CSV report saved to:[/green] {filepath}")
    return filepath
