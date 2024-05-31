import pandas as pd
import os
import argparse
from openpyxl import Workbook
from openpyxl.styles import PatternFill, Font, Border, Side
from openpyxl.utils import get_column_letter

def process_secrets_files(directory):
    results = []

    # Loop through each file ending in ".secrets"
    for file in os.listdir(directory):
        if file.endswith('.secrets'):
            # Check if the file is a regular file and is readable
            file_path = os.path.join(directory, file)
            if os.path.isfile(file_path) and os.access(file_path, os.R_OK):
                # Extract the hostname by removing the ".secretsdump.secrets" part from the filename
                hostname = os.path.basename(file).replace('.secretsdump.secrets', '').lower()
                
                # Run the grep commands against the file and append the results to the list
                with open(file_path, 'r') as f:
                    for line in f:
                        if "SCM:{" in line:
                            continue

                        if any(keyword in line for keyword in ['aes256', 'aes128', 'plain_password', 'des-cbc', 'dpapi', 'NL$KM', 'L$ASP.NET', 'L$_RasConn', 'aad3b435b51404eeaad3b435b51404ee', 'Security', 'RasDial', '| ', 'Version']):
                            continue

                        if ':' in line:
                            account, password = line.split(':', 1)
                            results.append([hostname, account.strip().lower(), password.strip()])

    return results

def process_sam_files(directory):
    results = []

    # Loop through each file ending in ".sam"
    for file in os.listdir(directory):
        if file.endswith('.sam'):
            # Check if the file is a regular file and is readable
            file_path = os.path.join(directory, file)
            if os.path.isfile(file_path) and os.access(file_path, os.R_OK):
                # Extract the hostname by removing the ".secretsdump.sam" part from the filename
                hostname = os.path.basename(file).replace('.secretsdump.sam', '').lower()
                
                # Run the grep commands against the file and append the results to the list
                with open(file_path, 'r') as f:
                    for line in f:
                        if any(keyword in line for keyword in ['Default', 'Guest', 'WDAGUtility']):
                            continue
                        
                        parts = line.strip().split(':')
                        if len(parts) >= 4:
                            account = parts[0].lower()
                            nt_hash = parts[3]
                            if nt_hash != '31d6cfe0d16ae931b73c59d7e0c089c0' and not account.startswith('_sc_gmsa_'):
                                results.append([hostname, account, nt_hash])

    return results

def apply_styles(sheet):
    # Define styles
    header_fill = PatternFill(start_color='000080', end_color='000080', fill_type='solid')  # Navy blue color
    header_font = Font(color='FFFFFF', bold=True)
    border_style = Side(border_style='thin', color='000000')
    border = Border(left=border_style, right=border_style, top=border_style, bottom=border_style)

    # Apply header styles
    for cell in sheet[1]:
        cell.fill = header_fill
        cell.font = header_font

    # Apply border to all cells
    for row in sheet.iter_rows(min_row=2, max_row=sheet.max_row, min_col=1, max_col=sheet.max_column):
        for cell in row:
            cell.border = border

    # Auto resize the columns to fit the content
    for column in sheet.columns:
        max_length = 0
        column_letter = get_column_letter(column[0].column)  # Get the column name
        for cell in column:
            try:
                if len(str(cell.value)) > max_length:
                    max_length = len(str(cell.value))
            except Exception:
                pass
        adjusted_width = (max_length + 2)
        sheet.column_dimensions[column_letter].width = adjusted_width

def main():
    parser = argparse.ArgumentParser(description="DumpInspector - A tool for auditing domain hosts' credential dumps.")
    parser.add_argument('-d', '--directory', help="<path-to-secretsdump-folder> containing the secretsdump output files.", required=True)
    parser.add_argument('-o', '--output', help="Output Excel file name (must end with .xlsx). [default: DumpInspector_Results.xlsx]", default="DumpInspector_Results.xlsx")
    
    args = parser.parse_args()

    # Validate output filename
    if not args.output.endswith('.xlsx'):
        parser.error("Output file name must end with .xlsx")

    # Process .secrets files
    secrets_data = process_secrets_files(args.directory)
    df_secrets = pd.DataFrame(secrets_data, columns=['HOST', 'ACCOUNT', 'PASSWORD']).drop_duplicates()

    # Process .sam files
    sam_data = process_sam_files(args.directory)
    df_sam = pd.DataFrame(sam_data, columns=['HOST', 'ACCOUNT', 'NT HASH'])

    # Keep only duplicates for local admin reuse
    df_sam = df_sam[df_sam.duplicated(subset=['ACCOUNT', 'NT HASH'], keep=False)]

    # Sort by ACCOUNT column
    df_sam = df_sam.sort_values(by='ACCOUNT')

    # Save to an Excel file with multiple sheets
    with pd.ExcelWriter(args.output, engine='openpyxl') as writer:
        # Write the Service Account Cleartext Audit data
        df_secrets.to_excel(writer, index=False, sheet_name='Service Account Cleartext Audit')

        # Write the Local Admin Reuse Audit data
        df_sam.to_excel(writer, index=False, sheet_name='Local Admin Reuse Audit')

        # Get the workbook and sheets
        workbook = writer.book
        secrets_sheet = writer.sheets['Service Account Cleartext Audit']
        sam_sheet = writer.sheets['Local Admin Reuse Audit']

        # Apply styles to both sheets
        apply_styles(secrets_sheet)
        apply_styles(sam_sheet)

if __name__ == "__main__":
    main()
