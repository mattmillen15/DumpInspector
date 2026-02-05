import pandas as pd
import os
import shutil
import argparse
import subprocess
import configparser
from openpyxl.styles import PatternFill, Font, Border, Side
from openpyxl.utils import get_column_letter
from tqdm import tqdm
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import re

def find_nxc(verbose=False):
    for cmd in ['nxc', 'netexec']:
        path = shutil.which(cmd)
        if path:
            if verbose:
                print(f"[VERBOSE] Found {cmd} at: {path}")
            return path

    shell = os.environ.get('SHELL', '/bin/bash')
    if verbose:
        print(f"[VERBOSE] Not in PATH, checking shell aliases via {shell}...")

    try:
        result = subprocess.run(
            [shell, '-i', '-c', 'command -v nxc || command -v netexec'],
            capture_output=True, text=True, timeout=10
        )
        for line in (result.stdout + result.stderr).strip().split('\n'):
            line = line.strip().strip("'\"")
            if line.startswith('/') and os.path.exists(line):
                if verbose:
                    print(f"[VERBOSE] Found via shell: {line}")
                return line
            if 'alias' in line and '=' in line:
                path = line.split('=', 1)[1].strip().strip("'\"")
                if os.path.exists(path):
                    if verbose:
                        print(f"[VERBOSE] Found via alias: {path}")
                    return path
    except:
        pass
    return None

def strip_ansi(text):
    return re.sub(r'\x1b\[[0-9;]*m', '', text)

def sanitize(text):
    if isinstance(text, str):
        return re.sub(r'[^\x20-\x7E]+', '', text)
    return text

def strip_hostname(filename):
    basename = os.path.basename(filename).lower()
    suffixes = [
        '.secretsdump.secrets', '_regsecrets.secrets', '.secretsdump.sam', '_regsecrets.sam',
        '.dpapi', '_dpapi.txt', '.dpapidump', '_dpapidump.txt',
        '.secrets', '.sam', '.txt'
    ]
    for suffix in suffixes:
        if basename.endswith(suffix):
            return basename[:-len(suffix)]
    return basename

def process_secrets_files(directory):
    skip_keywords = [
        'aes256', 'aes128', 'plain_password', 'des-cbc', 'dpapi', 'NL$KM',
        'L$ASP.NET', 'L$_RasConn', 'aad3b435b51404eeaad3b435b51404ee',
        'Security', 'RasDial', '| ', 'Version'
    ]
    results = []
    for file in os.listdir(directory):
        if not file.endswith('.secrets'):
            continue
        file_path = os.path.join(directory, file)
        if not (os.path.isfile(file_path) and os.access(file_path, os.R_OK)):
            continue
        hostname = strip_hostname(file)
        with open(file_path, 'r') as f:
            for line in f:
                if "SCM:{" in line or any(kw in line for kw in skip_keywords):
                    continue
                if ':' in line:
                    account, password = line.split(':', 1)
                    password = password.strip()
                    if len(password) <= 50:
                        results.append([sanitize(hostname), sanitize(account.strip().lower()), sanitize(password)])
    return results

def process_sam_files(directory):
    skip_accounts = ['Default', 'Guest', 'WDAGUtility']
    null_hash = '31d6cfe0d16ae931b73c59d7e0c089c0'
    results = []
    for file in os.listdir(directory):
        if not file.endswith('.sam'):
            continue
        file_path = os.path.join(directory, file)
        if not (os.path.isfile(file_path) and os.access(file_path, os.R_OK)):
            continue
        hostname = strip_hostname(file)
        with open(file_path, 'r') as f:
            for line in f:
                if any(kw in line for kw in skip_accounts):
                    continue
                parts = line.strip().split(':')
                if len(parts) >= 4:
                    account = parts[0].lower()
                    nt_hash = parts[3]
                    if nt_hash != null_hash and not account.startswith('_sc_gmsa_'):
                        results.append([sanitize(hostname), sanitize(account), sanitize(nt_hash)])
    return results

def process_dpapi_files(directory):
    results = []
    for file in os.listdir(directory):
        if 'dpapi' not in file.lower():
            continue
        file_path = os.path.join(directory, file)
        if not (os.path.isfile(file_path) and os.access(file_path, os.R_OK)):
            continue
        hostname = strip_hostname(file)
        with open(file_path, 'r', errors='ignore') as f:
            content = f.read()

        for block in content.split('[CREDENTIAL]')[1:]:
            if 'TaskScheduler:Task:' not in block:
                continue
            username = password = None
            for line in block.strip().split('\n'):
                line = line.strip()
                if line.startswith('Username') and ':' in line:
                    username = line.split(':', 1)[1].strip()
                elif username and line.startswith('Unknown') and ':' in line:
                    password = line.split(':', 1)[1].strip()
                    break
            if username and password:
                results.append([sanitize(hostname), sanitize(username), sanitize(password)])
    return results

def get_pwned_label():
    config_path = os.path.expanduser('~/.nxc/nxc.conf')
    if os.path.exists(config_path):
        config = configparser.ConfigParser()
        config.read(config_path)
        if 'nxc' in config and 'pwn3d_label' in config['nxc']:
            return config['nxc']['pwn3d_label']
    return 'Pwn3d!'

def log_message(message, log_file):
    with open(log_file, 'a') as log:
        log.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")

def verify_local_admin(hostname, account, nt_hash, pwned_label, nxc_path, log_file, verbose=False):
    command = f'{nxc_path} smb {hostname} -u {account} -H {nt_hash} --local-auth'
    try:
        if verbose:
            print(f"[VERBOSE] Running: {command}")
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=60)
        output = strip_ansi(result.stdout + result.stderr)
        log_message(f"Command: {command}\nOutput:\n{output}", log_file)
        if verbose:
            print(f"[VERBOSE] Output: {output.strip()}")
            found = pwned_label in output
            print(f"[VERBOSE] Looking for '{pwned_label}': {'FOUND' if found else 'NOT FOUND'}")
        if pwned_label in output:
            return (hostname, account, nt_hash)
    except subprocess.TimeoutExpired:
        log_message(f"Timeout: {command}", log_file)
        if verbose:
            print(f"[VERBOSE] Timeout")
    except Exception as e:
        log_message(f"Error verifying {account}@{hostname}: {e}", log_file)
        if verbose:
            print(f"[VERBOSE] Error: {e}")
    return None

def apply_styles(sheet):
    header_fill = PatternFill(start_color='000080', end_color='000080', fill_type='solid')
    header_font = Font(color='FFFFFF', bold=True)
    border = Border(
        left=Side(border_style='thin', color='000000'),
        right=Side(border_style='thin', color='000000'),
        top=Side(border_style='thin', color='000000'),
        bottom=Side(border_style='thin', color='000000')
    )

    for cell in sheet[1]:
        cell.fill = header_fill
        cell.font = header_font

    for row in sheet.iter_rows(min_row=2, max_row=sheet.max_row, min_col=1, max_col=sheet.max_column):
        for cell in row:
            cell.border = border

    for column in sheet.columns:
        max_len = max(len(str(cell.value or '')) for cell in column)
        sheet.column_dimensions[get_column_letter(column[0].column)].width = max_len + 2

def write_excel(dataframes, sheet_names, output_file):
    with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
        for df, name in zip(dataframes, sheet_names):
            df.to_excel(writer, index=False, sheet_name=name)
            apply_styles(writer.sheets[name])

def main():
    parser = argparse.ArgumentParser(description="DumpInspector - Audit credential dumps for reuse")
    parser.add_argument('-d', '--directory', required=True, help='Directory containing dump files')
    parser.add_argument('-o', '--output', default='DumpInspector_Results.xlsx', help='Output Excel file')
    parser.add_argument('--no-verify', action='store_true', help='Skip nxc verification of local admin')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show detailed output')
    args = parser.parse_args()

    if not args.output.endswith('.xlsx'):
        parser.error("Output file must end with .xlsx")

    log_file = 'debug.log'
    log_message("[+] DumpInspector started", log_file)

    print("\n[+] Auditing Secretsdump output...")
    secrets_data = process_secrets_files(args.directory)
    df_secrets = pd.DataFrame(secrets_data, columns=['HOST', 'ACCOUNT', 'PASSWORD']).drop_duplicates()
    if df_secrets.empty:
        print("    No plaintext service account credentials found.")

    sam_data = process_sam_files(args.directory)
    df_sam = pd.DataFrame(sam_data, columns=['HOST', 'ACCOUNT', 'NT HASH'])

    print("[+] Auditing DPAPI dump output for Task Scheduler credentials...")
    dpapi_data = process_dpapi_files(args.directory)
    df_dpapi = pd.DataFrame(dpapi_data, columns=['HOST', 'USERNAME', 'PASSWORD']).drop_duplicates()
    if df_dpapi.empty:
        print("    No Task Scheduler credentials found.")

    sheet_names = ['Service Account Cleartext Audit', 'Local Admin Reuse Audit', 'Task Scheduler Credentials']

    if not args.no_verify:
        unverified_file = args.output.replace('.xlsx', '_Unverified.xlsx')
        write_excel([df_secrets, df_sam, df_dpapi], sheet_names, unverified_file)
        print(f"\n[+] Unverified file created: {os.path.abspath(unverified_file)}")

        try:
            verify = input("\nVerify local admin access with nxc? (Y/N): ").strip().lower()
        except EOFError:
            verify = 'n'

        if verify == 'y':
            print()
            nxc_path = find_nxc(verbose=args.verbose)
            if not nxc_path:
                print("[!] ERROR: Could not find nxc or netexec.")
                return

            pwned_label = get_pwned_label()
            if args.verbose:
                print(f"[VERBOSE] Pwned label: '{pwned_label}'")
                print(f"[VERBOSE] Credentials to verify: {len(df_sam)}")

            verified = []
            if args.verbose:
                print("[VERBOSE] Single-threaded mode for verbose output\n")
                for row in df_sam.itertuples(index=False, name=None):
                    result = verify_local_admin(row[0], row[1], row[2], pwned_label, nxc_path, log_file, verbose=True)
                    if result:
                        verified.append(result)
                    print()
            else:
                with tqdm(total=len(df_sam), desc="Verifying local admin access") as pbar:
                    with ThreadPoolExecutor(max_workers=10) as executor:
                        futures = {
                            executor.submit(verify_local_admin, row[0], row[1], row[2], pwned_label, nxc_path, log_file): row
                            for row in df_sam.itertuples(index=False, name=None)
                        }
                        for future in as_completed(futures):
                            if future.result():
                                verified.append(future.result())
                            pbar.update(1)

            df_sam = pd.DataFrame(verified, columns=['HOST', 'ACCOUNT', 'NT HASH'])
            if df_sam.empty:
                print("\nNo valid local admin reuse identified.")
        else:
            print("\n[!] Skipping local admin verification.\n")
            return

    df_sam = df_sam[df_sam.duplicated(subset=['ACCOUNT', 'NT HASH'], keep=False)]
    df_sam = df_sam.sort_values(by=['NT HASH', 'ACCOUNT'])

    write_excel([df_secrets, df_sam, df_dpapi], sheet_names, args.output)
    print(f"\n[+] Results saved to: {os.path.abspath(args.output)}")

    try:
        sanitize_opt = input("\nCreate sanitized version (passwords redacted)? (Y/N): ").strip().lower()
    except EOFError:
        sanitize_opt = 'n'

    if sanitize_opt == 'y':
        sanitized_file = args.output.replace('.xlsx', '_Sanitized.xlsx')
        df_secrets_clean = df_secrets.drop(columns=['PASSWORD'], errors='ignore')
        df_sam_clean = df_sam.drop(columns=['NT HASH'], errors='ignore').sort_values(by=['ACCOUNT'])
        df_dpapi_clean = df_dpapi.drop(columns=['PASSWORD'], errors='ignore')
        write_excel([df_secrets_clean, df_sam_clean, df_dpapi_clean], sheet_names, sanitized_file)
        print(f"\n[+] Sanitized file created: {os.path.abspath(sanitized_file)}\n")

if __name__ == "__main__":
    main()
