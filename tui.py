from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

def display_section(title, data):
    if isinstance(data, dict):
        table = Table(title=title, box=box.SQUARE, expand=True)
        table.add_column("Key", style="bold cyan")
        table.add_column("Value", style="bold white")
        for key, value in data.items():
            table.add_row(str(key), str(value))
        console.print(table)
    elif isinstance(data, list):
        console.print(Panel.fit("\n".join(str(x) for x in data), title=title, box=box.SQUARE, border_style="cyan"))
    else:
        console.print(Panel.fit(str(data), title=title, border_style="cyan"))

def display_report(report):
    console.rule("[bold green]Mal-Protocol Scan Report[/bold green]")

    if "Hashes" in report:
        display_section("Hashes", report["Hashes"])
    if "Metadata" in report:
        display_section("Metadata", report["Metadata"])
    if "YARA Hits" in report:
        display_section("YARA Matches", report["YARA Hits"])
    if "IOCs" in report:
        display_section("Indicators of Compromise (IOCs)", report["IOCs"])
    if "VirusTotal" in report:
        display_section("VirusTotal Verdict", report["VirusTotal"])
    if "ExtractedFiles" in report:
        for i, ex in enumerate(report["ExtractedFiles"], start=1):
            console.rule(f"[bold yellow]Extracted File {i}[/bold yellow]")
            display_section("Path", ex.get("Path", "N/A"))
            display_section("Hashes", ex.get("Hashes", {}))
            display_section("YARA Hits", ex.get("YARA Hits", []))
            display_section("IOCs", ex.get("IOCs", {}))

    console.rule("[bold green]End of Report[/bold green]")
