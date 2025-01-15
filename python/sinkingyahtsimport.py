import requests
import time
import json
import psycopg2
from typing import List, Dict
from datetime import datetime, timedelta
from tqdm import tqdm
from collections import defaultdict
from colorama import init, Fore, Style

# Initialize colorama
init()

def get_db_connection():
    """Create a database connection"""
    return psycopg2.connect(
        dbname="REPLACEME",
        user="REPLACEME",
        password="REPLACEME",
        host="localhost",
        port="5432"
    )

def domain_exists_in_db(conn, domain: str) -> bool:
    """Check if domain exists in the database"""
    with conn.cursor() as cur:
        cur.execute('SELECT domain FROM public."Domain" WHERE domain = %s', (domain,))
        return cur.fetchone() is not None

class DomainStats:
    def __init__(self):
        self.start_time = time.time()
        self.skipped_domains = []
        self.success_domains = []
        self.error_domains = defaultdict(list)
        self.malicious_count = 0
        self.clean_count = 0

    def get_elapsed_time(self) -> str:
        elapsed = int(time.time() - self.start_time)
        return str(timedelta(seconds=elapsed))

    def add_skipped(self, domain: str):
        self.skipped_domains.append(domain)

    def add_success(self, domain: str, is_malicious: bool):
        self.success_domains.append(domain)
        if is_malicious:
            self.malicious_count += 1
        else:
            self.clean_count += 1

    def add_error(self, domain: str, error: str):
        self.error_domains[error].append(domain)

    def print_summary(self):
        print(f"\n{Fore.CYAN}=== Detailed Statistics ==={Style.RESET_ALL}")
        print(f"\n{Fore.CYAN}Processed Domains:{Style.RESET_ALL}")
        total = len(self.skipped_domains) + len(self.success_domains) + sum(len(d) for d in self.error_domains.values())
        print(f"├─ Total domains processed: {Fore.WHITE}{total}{Style.RESET_ALL}")
        print(f"├─ Skipped (already in DB): {Fore.YELLOW}{len(self.skipped_domains)}{Style.RESET_ALL}")
        print(f"├─ Successfully checked: {Fore.GREEN}{len(self.success_domains)}{Style.RESET_ALL}")
        print(f"│  ├─ Malicious: {Fore.RED}{self.malicious_count}{Style.RESET_ALL}")
        print(f"│  └─ Clean: {Fore.GREEN}{self.clean_count}{Style.RESET_ALL}")
        print(f"└─ Errors: {Fore.RED}{sum(len(d) for d in self.error_domains.values())}{Style.RESET_ALL}")

        if self.error_domains:
            print(f"\n{Fore.RED}Error Breakdown:{Style.RESET_ALL}")
            for error, domains in self.error_domains.items():
                print(f"├─ {error}: {Fore.RED}{len(domains)} domains{Style.RESET_ALL}")
                for domain in domains[:3]:
                    print(f"│  └─ Example: {Fore.YELLOW}{domain}{Style.RESET_ALL}")

        stats_data = {
            "skipped_domains": self.skipped_domains,
            "success_domains": {
                "malicious": [d for d in self.success_domains if d in self.success_domains[:self.malicious_count]],
                "clean": [d for d in self.success_domains if d in self.success_domains[self.malicious_count:]]
            },
            "error_domains": dict(self.error_domains)
        }

        with open("domain_check_stats.json", "w") as f:
            json.dump(stats_data, f, indent=2)
        print(f"\n{Fore.CYAN}Detailed statistics saved to domain_check_stats.json{Style.RESET_ALL}")

def check_domains(domains: List[str], bearer_token: str, conn, delay: float = 1.0):
    headers = {
        "Authorization": f"Bearer {bearer_token}",
        "Accept": "application/json"
    }

    results = []
    stats = DomainStats()
    total_domains = len(domains)

    progress = tqdm(
        total=total_domains,
        desc=f"{Fore.CYAN}Processing domains{Style.RESET_ALL}",
        unit="domain",
        ncols=100,
        position=0,
        leave=True,
        bar_format='{desc} |{bar}| {percentage:3.0f}% {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]'
    )

    status_bar = tqdm(total=0, position=1, bar_format='{desc}', leave=True)
    stats_bar = tqdm(total=0, position=2, bar_format='{desc}', leave=True)
    time_bar = tqdm(total=0, position=3, bar_format='{desc}', leave=True)

    # Add this function inside check_domains() before update_displays()
    def format_time(td):
        hours = td.seconds // 3600
        minutes = (td.seconds // 60) % 60
        seconds = td.seconds % 60
        return f"{hours}h {minutes}m {seconds}s"

    def update_displays(domain: str):
        processed = len(stats.success_domains) + len(stats.skipped_domains) + sum(len(d) for d in stats.error_domains.values())

        status_bar.set_description_str(
            f"{Fore.CYAN}Current domain:{Style.RESET_ALL} {Fore.WHITE}{domain[:50]}...{Style.RESET_ALL}"
        )

        stats_bar.set_description_str(
            f"{Fore.GREEN}Processed: {len(stats.success_domains)}{Style.RESET_ALL} | "
            f"{Fore.YELLOW}Skipped: {len(stats.skipped_domains)}{Style.RESET_ALL} | "
            f"{Fore.RED}Errors: {sum(len(d) for d in stats.error_domains.values())}{Style.RESET_ALL} | "
            f"{Fore.RED}Malicious: {stats.malicious_count}{Style.RESET_ALL}"
        )

        if processed > 0:
            avg_time_per_domain = (time.time() - stats.start_time) / processed
            domains_remaining = total_domains - processed
            eta = timedelta(seconds=int(avg_time_per_domain * domains_remaining))
            time_bar.set_description_str(
                f"{Fore.CYAN}Elapsed:{Style.RESET_ALL} {Fore.WHITE}{format_time(timedelta(seconds=int(time.time() - stats.start_time)))}{Style.RESET_ALL} | "
                f"{Fore.CYAN}ETA:{Style.RESET_ALL} {Fore.WHITE}{format_time(eta)}{Style.RESET_ALL} | "
                f"{Fore.CYAN}Avg:{Style.RESET_ALL} {Fore.WHITE}{avg_time_per_domain:.2f}s per domain{Style.RESET_ALL}"
            )

    for domain in domains:
        domain = domain.strip()
        update_displays(domain)

        if domain_exists_in_db(conn, domain):
            stats.add_skipped(domain)
            progress.update(1)
            continue

        try:
            response = requests.get(
                f"https://api.phish.directory/domain/check?domain={domain}",
                headers=headers
            )

            if response.status_code == 200:
                data = response.json()
                is_malicious = data.get('malicious', False)
                result = {
                    "domain": domain,
                    "status": "success",
                    "data": data
                }

                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO public."Domain" (
                            uuid, domain, malicious, createdAt, updatedAt, lastChecked
                        ) VALUES (
                            gen_random_uuid(), %s, %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
                        )
                        ON CONFLICT (domain)
                        DO UPDATE SET
                            malicious = EXCLUDED.malicious,
                            updatedAt = CURRENT_TIMESTAMP,
                            lastChecked = CURRENT_TIMESTAMP
                    """, (domain, is_malicious))
                conn.commit()

                stats.add_success(domain, is_malicious)

            else:
                result = {
                    "domain": domain,
                    "status": "error",
                    "error": f"HTTP {response.status_code}"
                }
                stats.add_error(domain, f"HTTP {response.status_code}")

        except Exception as e:
            result = {
                "domain": domain,
                "status": "error",
                "error": str(e)
            }
            stats.add_error(domain, str(e))

        results.append(result)
        progress.update(1)
        update_displays(domain)

        time.sleep(delay)

    progress.close()
    status_bar.close()
    stats_bar.close()
    time_bar.close()

    stats.print_summary()
    print(f"\n{Fore.CYAN}Total time elapsed: {Fore.WHITE}{stats.get_elapsed_time()}{Style.RESET_ALL}")

    return results

def main():
    bearer_token = "REPLACEME"

    print(f"{Fore.CYAN}Fetching domain list...{Style.RESET_ALL}")
    try:
        response = requests.get("https://phish.sinking.yachts/v2/all")
        domains = response.json()
        print(f"{Fore.GREEN}Retrieved {len(domains)} domains to process{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error fetching domains: {e}{Style.RESET_ALL}")
        return

    try:
        conn = get_db_connection()
    except Exception as e:
        print(f"{Fore.RED}Error connecting to database: {e}{Style.RESET_ALL}")
        return

    try:
        results = check_domains(domains, bearer_token, conn)

        print(f"\n{Fore.CYAN}Saving results...{Style.RESET_ALL}")
        with open("domain_check_results.json", "w") as f:
            json.dump(results, f, indent=2)

        print(f"{Fore.GREEN}Results saved to domain_check_results.json{Style.RESET_ALL}")

    finally:
        conn.close()

if __name__ == "__main__":
    main()
