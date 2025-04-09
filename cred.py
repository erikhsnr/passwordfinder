#!/usr/bin/env python3
import os
import re
import glob
from pathlib import Path
import time
#from tqdm import tqdm   For progress bar, install with: pip install tqdm

# Dictionary of credential patterns with fixed escaping
credential_patterns = {
    "Artifactory API Token": r'(?:\s|=|:|"|^)AKC[a-zA-Z0-9]{10,}',
    "Artifactory Password": r'(?:\s|=|:|"|^)AP[\dABCDEF][a-zA-Z0-9]{8,}',
    "Authorization Basic": r'basic [a-zA-Z0-9_\-:\.=]+',  # Fixed escaping
    "Authorization Bearer": r'bearer [a-zA-Z0-9_\-\.=]+',  # Fixed escaping
    "AWS Client ID": r'(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
    "AWS MWS Key": r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    "AWS Secret Key": r'(?i)aws(.{0,20})?(?-i)[\'"][0-9a-zA-Z\/+]{40}[\'"]',
    # "Base32": r'(?:[A-Z2-7]{8})*(?:[A-Z2-7]{2}={6}|[A-Z2-7]{4}={4}|[A-Z2-7]{5}={3}|[A-Z2-7]{7}=)?',
    "Base64": r'(eyJ|YTo|Tzo|PD[89]|aHR0cHM6L|aHR0cDo|rO0)[a-zA-Z0-9+/]+={0,2}',
    "Basic Auth Credentials": r'(?<=://)([a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-zA-Z]+)',
    "Cloudinary Basic Auth": r'cloudinary://[0-9]{15}:[0-9A-Za-z]+@[a-z]+',
    "Facebook Access Token": r'EAACEdEose0cBA[0-9A-Za-z]+',
    "Facebook Client ID": r'(?i)(facebook|fb)(.{0,20})?[\'"][0-9]{13,17}',
    "Facebook Oauth": r'[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*[\'|"][0-9a-f]{32}[\'|"]',
    "Facebook Secret Key": r'(?i)(facebook|fb)(.{0,20})?(?-i)[\'"][0-9a-f]{32}',
    "Github": r'(?i)github(.{0,20})?(?-i)[\'"][0-9a-zA-Z]{35,40}',
    "Google API Key": r'AIza[0-9A-Za-z\-_]{35}',  # Fixed escaping
    "Google Cloud Platform API Key": r'(?i)(google|gcp|youtube|drive|yt)(.{0,20})?[\'"]AIza[0-9a-z\-_]{35}[\'"]',  # Fixed escaping
    "Google Drive API Key": r'AIza[0-9A-Za-z\-_]{35}',  # Fixed escaping
    "Google Drive Oauth": r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
    "Google Gmail API Key": r'AIza[0-9A-Za-z\-_]{35}',  # Fixed escaping
    "Google Gmail Oauth": r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
    "Google Oauth Access Token": r'ya29\.[0-9A-Za-z\-_]+',  # Fixed escaping
    "Google Youtube API Key": r'AIza[0-9A-Za-z\-_]{35}',  # Fixed escaping
    "Google Youtube Oauth": r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
    "Heroku API Key": r'[h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}',
    #"IPv4": r'\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}\b',
    #"IPv6": r'(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))',
    #"Javascript Variables": r'(?:const|let|var)\s+(\w+?)(?=[;.=\s])',  # Fixed pattern
    "LinkedIn Client ID": r'(?i)linkedin(.{0,20})?(?-i)[\'"][0-9a-z]{12}[\'"]',
    "LinkedIn Secret Key": r'(?i)linkedin(.{0,20})?[\'"][0-9a-z]{16}[\'"]',
    "Mailchamp API Key": r'[0-9a-f]{32}-us[0-9]{1,2}',
    "Mailgun API Key": r'key-[0-9a-zA-Z]{32}',
    "Mailto:": r'mailto:[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+',  # Fixed lookbehind
    "MD5 Hash": r'[a-f0-9]{32}',
    "Picatic API Key": r'sk_live_[0-9a-z]{32}',
    "Slack Token": r'xox[baprs]-([0-9a-zA-Z]{10,48})?',
    "Slack Webhook": r'https://hooks.slack.com/services/T[a-zA-Z0-9_]{10}/B[a-zA-Z0-9_]{10}/[a-zA-Z0-9_]{24}',
    "Stripe API Key": r'(pk|sk|rk)_(test|live)_[A-Za-z0-9]+',
    "Square Access Token": r'sqOatp-[0-9A-Za-z\-_]{22}',  # Fixed escaping
    "Square Oauth Secret": r'sq0csp-[ 0-9A-Za-z\-_]{43}',  # Fixed escaping
    "Twilio API Key": r'SK[0-9a-fA-F]{32}',
    "Twitter Client ID": r'(?i)twitter(.{0,20})?[\'"][0-9a-z]{18,25}',
    "Twitter Oauth": r'[t|T][w|W][i|I][t|T][t|T][e|E][r|R].{0,30}[\'"\s][0-9a-zA-Z]{35,44}[\'"\s]',
    "Twitter Secret Key": r'(?i)twitter(.{0,20})?[\'"][0-9a-z]{35,44}',
    #"Vault Token": r'[sb]\.[a-zA-Z0-9]{24}',
    #"URL Parameter": r'[?&][a-zA-Z0-9_]+=',  # Fixed lookbehind
    # "URLs with HTTP Protocol": r'https?://(www\.)?[-a-zA-Z0-9@:%._+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_+.~#?&//=]*)',
    # "URLs without Protocol": r'[-a-zA-Z0-9@:%._+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_+.~#?&//=]*)'
}

def is_binary_file(file_path):
    """Check if file is binary"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            f.read(1024)
        return False
    except UnicodeDecodeError:
        return True
    except Exception:
        return True  # Consider any error as binary for safety

def get_all_files(directory='.'):
    """Get all files in the directory recursively"""
    files = []
    for file_path in glob.iglob(f'{directory}/**', recursive=True):
        if os.path.isfile(file_path):
            files.append(file_path)
    return files

def find_credentials(directory='.'):
    """Find credentials in files"""
    results = []
    cred_counts = {cred_type: 0 for cred_type in credential_patterns.keys()}

    # Get the current directory as the base path for relative paths
    base_path = os.path.abspath(directory)

    # Get list of files first to show accurate progress
    print("Gathering files list...")
    all_files = get_all_files(directory)
    total_files = len(all_files)
    print(f"Found {total_files} files to scan")

    # Track processed files and time
    processed_files = 0
    skipped_files = 0

    # Process each file with simple progress indicator
    for i, file_path in enumerate(all_files, 1):
        # Print progress every 100 files
        if i % 100 == 0:
            percent = (i / total_files) * 100
            print(f"[{percent:.1f}%] Scanned {i}/{total_files} files, found {len(results)} credentials")

        if is_binary_file(file_path):
            skipped_files += 1
            continue

        try:
            # Get relative path from current directory
            rel_path = os.path.relpath(file_path, start=base_path)

            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.splitlines()

                for line_num, line in enumerate(lines, 1):
                    for cred_type, pattern in credential_patterns.items():
                        try:
                            matches = re.finditer(pattern, line)
                            for match in matches:
                                credential = match.group(0)

                                # Only add if not already found (avoid duplicates)
                                is_duplicate = False
                                for existing in results:
                                    if (existing['file_path'] == rel_path and
                                        existing['line_num'] == line_num and
                                        existing['credential'] == credential):
                                        is_duplicate = True
                                        break

                                if not is_duplicate:
                                    results.append({
                                        'file_path': rel_path,
                                        'cred_type': cred_type,
                                        'line_num': line_num,
                                        'line': line.strip(),
                                        'credential': credential
                                    })
                                    cred_counts[cred_type] += 1

                                    # Print immediate feedback when credential is found
                                    print(f"Found {cred_type} in {rel_path}:{line_num}")
                        except re.error:
                            # Skip patterns with regex errors for this line
                            pass
        except Exception as e:
            print(f"Error processing file {file_path}: {str(e)}")
            skipped_files += 1

    # Print summary stats
    print("\n--- Scan Summary ---")
    print(f"Total files scanned: {total_files - skipped_files}")
    print(f"Files skipped (binary/errors): {skipped_files}")
    print(f"Total credentials found: {len(results)}")

    # Print breakdown by credential type
    print("\n--- Credentials Breakdown ---")
    for cred_type, count in sorted(cred_counts.items(), key=lambda x: x[1], reverse=True):
        if count > 0:
            print(f"{cred_type}: {count}")

    return results

def write_to_markdown(results, output_file='cred.md'):
    """Write results to markdown table"""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('# Credential Scan Results\n\n')

        # Summary statistics
        f.write('## Summary\n')
        f.write(f'* Total credentials found: {len(results)}\n')

        # Count by type
        cred_counts = {}
        for result in results:
            cred_type = result['cred_type']
            cred_counts[cred_type] = cred_counts.get(cred_type, 0) + 1

        if cred_counts:
            f.write('* Types of credentials found:\n')
            for cred_type, count in sorted(cred_counts.items(), key=lambda x: x[1], reverse=True):
                f.write(f'  * {cred_type}: {count}\n')

        f.write('\n## Detailed Results\n\n')
        f.write('| File Path | Credential Type | Line Number | Credential | Code |\n')
        f.write('|-----------|----------------|-------------|------------|------|\n')

        for result in results:
            # Escape pipe characters in strings to prevent breaking the markdown table
            file_path = result['file_path'].replace('|', '\\|')
            cred_type = result['cred_type'].replace('|', '\\|')
            credential = result['credential'].replace('|', '\\|')
            line = result['line'].strip().replace('|', '\\|')

            f.write(f"| {file_path} | {cred_type} | {result['line_num']} | `{credential}` | `{line}` |\n")

def main():
    print("Starting credential scan...")
    print(f"Using {len(credential_patterns)} different patterns to identify credentials")

    # Start the scan
    start_time = time.time()
    results = find_credentials()
    end_time = time.time()

    # Show completion message with timing
    duration = end_time - start_time
    print(f"\nScan completed in {duration:.2f} seconds.")
    print(f"Found {len(results)} potential credentials")

    # Write results to file
    write_to_markdown(results)
    print(f"Results written to cred.md")

if __name__ == "__main__":
    main()
