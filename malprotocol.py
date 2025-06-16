import sys
import os
import argparse
from rich import print
from rich.panel import Panel
from rich.prompt import Confirm
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

import core_scanner
import vt_lookup
import report
import tui
import ai_analysis

console = Console()

def show_banner():
    banner_text = r"""
ooo        ooooo       .o.       ooooo                      .o     .oooo.     .oooo.   ooooo        
`88.       .888'      .888.      `888'                    .d88    d8P'`Y8b   d8P'`Y8b  `888'        
 888b     d'888      .8"888.      888                   .d'888   888    888 888    888  888         
 8 Y88. .P  888     .8' `888.     888                 .d'  888   888    888 888    888  888         
 8  `888'   888    .88ooo8888.    888         8888888 88ooo888oo 888    888 888    888  888         
 8    Y     888   .8'     `888.   888       o              888   `88b  d88' `88b  d88'  888       o 
o8o        o888o o88o     o8888o o888ooooood8             o888o   `Y8bd8P'   `Y8bd8P'  o888ooooood8 
"""
    console.print(Panel.fit(banner_text, style="bold green"))
    console.print("[bold blue]Created by - ig.masio / ig.darmik[/bold blue]\n")


def extract_ai_risk_level(ai_output: str) -> str:
    for line in ai_output.splitlines():
        if line.strip().lower().startswith("risk:"):
            return line.split(":")[1].strip().lower()
    return "unknown"


def contains_reverse_shell(yara_hits):
    reverse_keywords = [
        "reverse_shell", "netcat_reverse", "cmd.exe /c", "bash -i", "nc -e",
        "python -c", "socket.connect", "connect_back", "powershell -nop"
    ]
    for hit in yara_hits:
        for keyword in reverse_keywords:
            if keyword.lower() in hit.lower():
                return True
    return False


def calculate_risk_percentage(vt_mal, yara_hits, total_iocs, ai_risk_level):
    score = 0

    # VirusTotal (up to 40%)
    if vt_mal:
        score += min((vt_mal / 70) * 40, 40)

    # YARA (up to 15%)
    if yara_hits:
        score += min(len(yara_hits) * 3, 15)

    # IOCs (up to 5%)
    score += min(total_iocs, 5)

    # AI Risk (up to 40%)
    if ai_risk_level == "malicious":
        score += 40
    elif ai_risk_level == "suspicious":
        score += 20

    # Override if reverse shell pattern detected
    if contains_reverse_shell(yara_hits):
        score = max(score, 35)

    return round(min(score, 100), 2)


def main():
    parser = argparse.ArgumentParser(description="Mal-Protocol: File Malware Scanner")
    parser.add_argument("file", help="Path to the file to scan")
    parser.add_argument("--no-vt", action="store_true", help="Skip VirusTotal lookup")
    parser.add_argument("--json", action="store_true", help="Save JSON report")
    parser.add_argument("--csv", action="store_true", help="Save CSV report")
    args = parser.parse_args()

    if not os.path.exists(args.file):
        console.print("[red]❌ Error: File does not exist.[/red]")
        sys.exit(1)

    show_banner()

    with Progress(SpinnerColumn(), TextColumn("[bold blue]Scanning file..."), transient=True) as progress:
        task = progress.add_task("scan")
        scan_result = core_scanner.scan_file(args.file)
        progress.update(task, advance=100)

    if not args.no_vt:
        with Progress(SpinnerColumn(), TextColumn("[bold yellow]Querying VirusTotal..."), transient=True) as progress:
            task = progress.add_task("vt")
            vt_result = vt_lookup.get_vt_report(args.file)
            scan_result["VirusTotal"] = vt_result
            progress.update(task, advance=100)
    else:
        vt_result = {}

    console.rule("[bold green]🔎 Scan Summary[/bold green]")
    tui.display_report(scan_result)

    console.rule("[bold cyan]🤖 AI Analysis[/bold cyan]")
    ai_output = ai_analysis.analyze_with_ai(scan_result)
    console.print(ai_output)

    # Get metrics
    vt_mal = vt_result.get("malicious_count", 0) if isinstance(vt_result, dict) else 0
    yara_hits = scan_result.get("YARA Hits", [])
    iocs = scan_result.get("IOCs", {})
    total_iocs = sum(len(v) for v in iocs.values()) if isinstance(iocs, dict) else 0
    ai_risk = extract_ai_risk_level(ai_output)

    # Calculate percentage
    risk_percent = calculate_risk_percentage(vt_mal, yara_hits, total_iocs, ai_risk)

    console.rule("[bold magenta]🧠 Final Verdict[/bold magenta]")

    if risk_percent >= 80:
        console.print(f"[bold red]🚨 This file is likely malicious. Risk: {risk_percent}%[/bold red]")
    elif risk_percent >= 50:
        console.print(f"[yellow]⚠️ This file looks suspicious. Risk: {risk_percent}%[/yellow]")
    elif risk_percent >= 20:
        console.print(f"[orange1]⚠️ This file has minor suspicious indicators. Risk: {risk_percent}%[/orange1]")
    else:
        console.print(f"[bold green]✅ This file looks safe. Risk: {risk_percent}%[/bold green]")

    if not args.json and not args.csv:
        if Confirm.ask("💾 Save JSON report?", default=True):
            report.save_as_json(scan_result)
        if Confirm.ask("📊 Save CSV report?", default=False):
            report.save_as_csv(scan_result)
    else:
        if args.json:
            report.save_as_json(scan_result)
        if args.csv:
            report.save_as_csv(scan_result)

    console.print("\n[bold cyan]📁 Scan completed. Stay safe![/bold cyan]")


if __name__ == "__main__":
    main()
