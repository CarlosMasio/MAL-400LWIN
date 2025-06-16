import os
import hashlib
import yara
import re
import json
import tempfile
import shutil
from zipfile import ZipFile
import py7zr
from rich import print


def calculate_hashes(file_path):
    hashes = {'MD5': '', 'SHA1': '', 'SHA256': ''}
    with open(file_path, 'rb') as f:
        data = f.read()
        hashes['MD5'] = hashlib.md5(data).hexdigest()
        hashes['SHA1'] = hashlib.sha1(data).hexdigest()
        hashes['SHA256'] = hashlib.sha256(data).hexdigest()
    return hashes


def extract_metadata(file_path):
    try:
        from hachoir.metadata import extractMetadata
        from hachoir.parser import createParser
        parser = createParser(file_path)
        if not parser:
            return {}
        metadata = extractMetadata(parser)
        return dict(metadata.exportDictionary()) if metadata else {}
    except:
        return {}


def yara_scan(file_path, rules_path='rules/basic_rules.yar'):
    try:
        if not os.path.exists(rules_path):
            print(f"[yellow]⚠️ YARA rules not found: {rules_path}[/yellow]")
            return []
        rules = yara.compile(filepath=rules_path)
        matches = rules.match(filepath=file_path)
        return [match.rule for match in matches]
    except yara.Error as e:
        print(f"[red]YARA error: {e}[/red]")
        return []


def extract_archives(file_path, temp_dir):
    extracted_files = []
    try:
        if file_path.endswith('.zip'):
            with ZipFile(file_path, 'r') as zf:
                zf.extractall(temp_dir)
                for name in zf.namelist():
                    full_path = os.path.join(temp_dir, name)
                    if os.path.isfile(full_path):
                        extracted_files.append(full_path)
        elif file_path.endswith('.7z'):
            with py7zr.SevenZipFile(file_path, mode='r') as zf:
                zf.extractall(path=temp_dir)
                for root, _, files in os.walk(temp_dir):
                    for f in files:
                        extracted_files.append(os.path.join(root, f))
    except Exception as e:
        print(f"[red]Archive extraction failed:[/red] {e}")
    return extracted_files


def extract_iocs(file_path):
    try:
        with open(file_path, 'r', errors='ignore') as f:
            content = f.read()
    except:
        return {'IPs': [], 'URLs': [], 'Domains': []}

    # Updated: exclude local/private IPs, add stricter domain detection
    ip_pattern = r'\b(?!(127\.|192\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])))(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    url_pattern = r'https?:\/\/[^\s"\'<>]+'
    domain_pattern = r'\b[a-zA-Z0-9.-]+\.(com|net|org|info|biz|ru|cn|xyz|link)\b'

    return {
        'IPs': list(set(re.findall(ip_pattern, content))),
        'URLs': list(set(re.findall(url_pattern, content))),
        'Domains': list(set(re.findall(domain_pattern, content)))
    }


def scan_file(file_path):
    print(f"[bold green]🧪 Scanning:[/bold green] {file_path}")
    result = {}

    result['Hashes'] = calculate_hashes(file_path)
    result['Metadata'] = extract_metadata(file_path)
    result['YARA Hits'] = yara_scan(file_path)
    result['IOCs'] = extract_iocs(file_path)

    with tempfile.TemporaryDirectory() as temp_dir:
        extracted = extract_archives(file_path, temp_dir)
        if extracted:
            result['ExtractedFiles'] = []
            for ex_file in extracted:
                try:
                    info = {
                        'Path': ex_file,
                        'Hashes': calculate_hashes(ex_file),
                        'YARA Hits': yara_scan(ex_file),
                        'IOCs': extract_iocs(ex_file)
                    }
                    result['ExtractedFiles'].append(info)
                except Exception as e:
                    print(f"[red]Error scanning extracted file {ex_file}:[/red] {e}")
    return result
