import os
import argparse
from dotenv import load_dotenv
from rich.console import Console

from modules.network_info import get_network_details
from modules.abusedb_info import get_abuse_score


load_dotenv()
console = Console()

def print_result(title, data):
    console.print(f"\n[bold yellow]=== {title} ===[/bold yellow]")

    # Ellenőrizzük, hogy történt-e hiba a lekérdezés során
    if "error" in data:
        console.print(f"[bold red]HIBA:[/bold red] {data['error']}")
        return

    # Végigmegyünk az adatokon és kiírjuk őket kulcs: érték párokban
    for key, value in data.items():
        clean_key = key.replace("_", " ").title()

        # Speciális színezés az Abuse Score-nak
        if key == "score":
            color = "red" if value > 50 else "yellow" if value > 0 else "green"
            console.print(f"[cyan]{clean_key}:[/cyan] [{color}]{value}%[/{color}]")
        else:
            console.print(f"[cyan]{clean_key}:[/cyan] [white]{value}[/white]")


def main():
    # Arguments
    parser = argparse.ArgumentParser(description="IP Enrichment Tool")
    parser.add_argument("ip", help="IP address")
    args = parser.parse_args()
    target_ip = args.ip

    # Itt hívjuk meg a modulokban megírt függvényeket
    with console.status("[bold green]Requesting data..."):
        net_data = get_network_details(target_ip)
        print_result("Network Information", net_data)
        abuseipdb_data = get_abuse_score(target_ip)
        print_result("AbuseIPDB Information", abuseipdb_data)


if __name__ == "__main__":
    main()