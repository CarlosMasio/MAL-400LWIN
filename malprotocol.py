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

    console.rule("[bold green]🔎 Scan Summary[/bold green]")
    tui.display_report(scan_result)

    # 🤖 AI analysis
    console.rule("[bold cyan]🤖 AI Analysis[/bold cyan]")
    ai_summary = ai_analysis.analyze_with_ai(scan_result)
    console.print(ai_summary)

    # Human-readable final verdict
    console.rule("[bold magenta]🧠 Final Verdict[/bold magenta]")

    vt = scan_result.get("VirusTotal", {})
    yara_hits = scan_result.get("YARA Hits", [])
    iocs = scan_result.get("IOCs", {})
    extracted = scan_result.get("ExtractedFiles", [])

    vt_mal = vt.get("malicious_count", 0) if isinstance(vt, dict) else 0
    total_yara = len(yara_hits)
    total_iocs = sum(len(v) for v in iocs.values()) if isinstance(iocs, dict) else 0

    if vt_mal >= 10:
        console.print(f"[bold red]🚨 This file looks dangerous! Many antivirus engines reported it as harmful.[/bold red]")
    elif vt_mal > 0 and total_yara > 0:
        console.print(f"[orange1]⚠️ This file shows signs of being suspicious — a few antivirus tools and scan rules flagged it.[/orange1]")
    elif total_yara > 2 or total_iocs > 5:
        console.print("[yellow]⚠️ This file has some unusual or suspicious content, but it may still be safe.[/yellow]")
    elif vt_mal > 0:
        console.print(f"[orange1]⚠️ A few antivirus tools flagged this file, but we found no other strong signs of danger.[/orange1]")
    else:
        console.print("[bold green]✅ This file looks safe. No threats or suspicious behavior were found.[/bold green]")

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
