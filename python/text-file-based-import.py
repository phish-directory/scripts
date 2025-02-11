import asyncio
import aiohttp
import psycopg2
import time
from typing import List, Dict, Set
from datetime import datetime, timedelta
from tqdm import tqdm
from collections import defaultdict
from colorama import init, Fore, Style

# Initialize colorama
init()

BATCH_SIZE = 50  # Number of domains to process in parallel
DB_BATCH_SIZE = 1000  # Number of domains to check in DB at once

def read_domain_list(filename: str) -> List[str]:
    """Read domains from a text file"""
    try:
        with open(filename, 'r') as f:
            # Read lines and strip whitespace
            domains = [line.strip() for line in f if line.strip()]
        print(f"{Fore.GREEN}Successfully read {len(domains)} domains from {filename}{Style.RESET_ALL}")
        return domains
    except Exception as e:
        print(f"{Fore.RED}Error reading domain list: {e}{Style.RESET_ALL}")
        return []

def get_db_connection():
    """Create a database connection"""
    return psycopg2.connect(
        dbname="api_dark_brook_8284",
        user="api_dark_brook_8284",
        password="DB PASSWORD",
        host="localhost",
        port="25432"
    )

def domains_exist_in_db(conn, domains: List[str]) -> Set[str]:
    """Check which domains already exist in the database"""
    with conn.cursor() as cur:
        placeholders = ','.join(['%s'] * len(domains))
        cur.execute(f'SELECT domain FROM public."Domain" WHERE domain IN ({placeholders})', domains)
        return {row[0] for row in cur.fetchall()}

class DomainStats:
    def __init__(self):
        self.start_time = time.time()
        self.skipped_domains = []
        self.success_domains = []
        self.error_domains = defaultdict(list)
        self.malicious_count = 0
        self.clean_count = 0
        self.rate_limited_count = 0

    def add_skipped(self, domain: str):
        self.skipped_domains.append(domain)

    def add_success(self, domain: str, is_malicious: bool):
        self.success_domains.append(domain)
        if is_malicious:
            self.malicious_count += 1
        else:
            self.clean_count += 1

    def add_error(self, domain: str, error: str):
        if error == "Rate limit exceeded":
            self.rate_limited_count += 1
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
        print(f"   └─ Rate Limited: {Fore.YELLOW}{self.rate_limited_count}{Style.RESET_ALL}")

        if self.error_domains:
            print(f"\n{Fore.RED}Error Breakdown:{Style.RESET_ALL}")
            for error, domains in self.error_domains.items():
                print(f"├─ {error}: {Fore.RED}{len(domains)} domains{Style.RESET_ALL}")
                for domain in domains[:3]:
                    print(f"│  └─ Example: {Fore.YELLOW}{domain}{Style.RESET_ALL}")

async def check_single_domain(session, domain: str, bearer_token: str):
    """Check a single domain with rate limit handling"""
    try:
        async with session.get(
            f"https://api.phish.directory/domain/check?domain={domain}",
            headers={
                "Authorization": f"Bearer {bearer_token}",
                "Accept": "application/json"
            }
        ) as response:
            if response.status == 200:
                data = await response.json()
                return {
                    "domain": domain,
                    "status": "success",
                    "data": data
                }
            elif response.status == 429:  # Rate limit exceeded
                return {
                    "domain": domain,
                    "status": "error",
                    "error": "Rate limit exceeded"
                }
            else:
                return {
                    "domain": domain,
                    "status": "error",
                    "error": f"HTTP {response.status}"
                }
    except Exception as e:
        return {
            "domain": domain,
            "status": "error",
            "error": str(e)
        }

async def check_domain_batch(session, domains: List[str], bearer_token: str) -> List[Dict]:
    """Check a batch of domains concurrently"""
    tasks = []
    for domain in domains:
        # Add a small delay between creating tasks to help prevent rate limiting
        if tasks:
            await asyncio.sleep(0.1)  # 100ms delay between requests
        tasks.append(check_single_domain(session, domain, bearer_token))
    return await asyncio.gather(*tasks)

async def process_domains(domains: List[str], bearer_token: str, conn):
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

    def format_time(td):
        hours = td.seconds // 3600
        minutes = (td.seconds // 60) % 60
        seconds = td.seconds % 60
        return f"{hours}h {minutes}m {seconds}s"

    def update_displays(current_domains: List[str]):
        processed = len(stats.success_domains) + len(stats.skipped_domains) + sum(len(d) for d in stats.error_domains.values())

        status_bar.set_description_str(
            f"{Fore.CYAN}Current batch:{Style.RESET_ALL} {Fore.WHITE}{', '.join(current_domains[:3])}...{Style.RESET_ALL}"
        )

        stats_bar.set_description_str(
            f"{Fore.GREEN}Processed: {len(stats.success_domains)}{Style.RESET_ALL} | "
            f"{Fore.YELLOW}Skipped: {len(stats.skipped_domains)}{Style.RESET_ALL} | "
            f"{Fore.RED}Errors: {sum(len(d) for d in stats.error_domains.values())}{Style.RESET_ALL} | "
            f"{Fore.YELLOW}Rate Limited: {stats.rate_limited_count}{Style.RESET_ALL} | "
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

    async with aiohttp.ClientSession() as session:
        # Process domains in batches
        for i in range(0, len(domains), DB_BATCH_SIZE):
            db_batch = domains[i:i + DB_BATCH_SIZE]

            # Check which domains exist in DB
            existing_domains = domains_exist_in_db(conn, db_batch)
            new_domains = [d for d in db_batch if d not in existing_domains]

            # Update stats for skipped domains
            for domain in existing_domains:
                stats.add_skipped(domain)
            progress.update(len(existing_domains))

            # Process new domains in smaller batches
            for j in range(0, len(new_domains), BATCH_SIZE):
                batch = new_domains[j:j + BATCH_SIZE]
                update_displays(batch)

                results = await check_domain_batch(session, batch, bearer_token)

                # Process results
                for result in results:
                    if result['status'] == 'success':
                        stats.add_success(
                            result['domain'],
                            result['data'].get('malicious', False)
                        )
                    else:
                        stats.add_error(result['domain'], result['error'])

                progress.update(len(batch))
                update_displays(batch)

    progress.close()
    status_bar.close()
    stats_bar.close()
    time_bar.close()

    stats.print_summary()
    print(f"\n{Fore.CYAN}Total time elapsed: {Fore.WHITE}{format_time(timedelta(seconds=int(time.time() - stats.start_time)))}{Style.RESET_ALL}")

async def main():
    bearer_token = "INSERT TOKEN HERE"

    print(f"{Fore.CYAN}Reading domain list from file...{Style.RESET_ALL}")
    domains = read_domain_list("domain-list.txt")
    if not domains:
        return

    try:
        conn = get_db_connection()
        await process_domains(domains, bearer_token, conn)
    except Exception as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
    finally:
        if conn is not None:
            conn.close()

if __name__ == "__main__":
    asyncio.run(main())%
