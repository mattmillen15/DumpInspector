import pandas as pd
import os
from openpyxl import Workbook
from openpyxl.styles import PatternFill, Font, Border, Side
from openpyxl.utils import get_column_letter

# Function to process .secrets files for Service Account Cleartext Audit
def process_secrets_files():
    results = []

    # Loop through each file ending in ".secrets"
    for file in os.listdir('.'):
        if file.endswith('.secrets'):
            # Check if the file is a regular file and is readable
            if os.path.isfile(file) and os.access(file, os.R_OK):
                # Extract the hostname by removing the ".secretsdump.secrets" part from the filename
                hostname = os.path.basename(file).replace('.secretsdump.secrets', '').lower()
                
                # Run the grep commands against the file and append the results to the list
                with open(file, 'r') as f:
                    for line in f:
                        if "SCM:{" in line:
                            continue

                        if any(keyword in line for keyword in ['aes256', 'aes128', 'plain_password', 'des-cbc', 'dpapi', 'NL$KM', 'L$ASP.NET', 'L$_RasConn', 'aad3b435b51404eeaad3b435b51404ee', 'Security', 'RasDial', '| ', 'Version']):
                            continue

                        if ':' in line:
                            account, password = line.split(':', 1)
                            results.append([hostname, account.strip().lower(), password.strip()])

    return results

# Function to process .sam files for Local Admin Reuse Audit
def process_sam_files():
    results = []

    # Loop through each file ending in ".sam"
    for file in os.listdir('.'):
        if file.endswith('.sam'):
            # Check if the file is a regular file and is readable
            if os.path.isfile(file) and os.access(file, os.R_OK):
                # Extract the hostname by removing the ".secretsdump.sam" part from the filename
                hostname = os.path.basename(file).replace('.secretsdump.sam', '').lower()
                
                # Run the grep commands against the file and append the results to the list
                with open(file, 'r') as f:
                    for line in f:
                        if any(keyword in line for keyword in ['Default', 'Guest', 'WDAGUtility']):
                            continue
                        
                        parts = line.strip().split(':')
                        if len(parts) >= 4:
                            account = parts[0].lower()
                            nt_hash = parts[3]
                            if nt_hash != '31d6cfe0d16ae931b73c59d7e0c089c0':
                                results.append([hostname, account, nt_hash])

    return results

# Create the output file and write the header
output_file = 'CredAudit_Results.xlsx'

# Process .secrets files
secrets_data = process_secrets_files()
df_secrets = pd.DataFrame(secrets_data, columns=['HOST', 'ACCOUNT', 'PASSWORD']).drop_duplicates()

# Process .sam files
sam_data = process_sam_files()
df_sam = pd.DataFrame(sam_data, columns=['HOST', 'ACCOUNT', 'NT HASH'])

# Keep only duplicates for local admin reuse
df_sam = df_sam[df_sam.duplicated(subset=['ACCOUNT', 'NT HASH'], keep=False)]

# Sort by ACCOUNT column
df_sam = df_sam.sort_values(by='ACCOUNT')

# Save to an Excel file with multiple sheets
with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
    # Write the Service Account Cleartext Audit data
    df_secrets.to_excel(writer, index=False, sheet_name='Service Account Cleartext Audit')

    # Write the Local Admin Reuse Audit data
    df_sam.to_excel(writer, index=False, sheet_name='Local Admin Reuse Audit')

    # Get the workbook and sheets
    workbook = writer.book
    secrets_sheet = writer.sheets['Service Account Cleartext Audit']
    sam_sheet = writer.sheets['Local Admin Reuse Audit']

    # Define styles
    header_fill = PatternFill(start_color='000080', end_color='000080', fill_type='solid')  # Navy blue color
    header_font = Font(color='FFFFFF', bold=True)
    border_style = Side(border_style='thin', color='000000')
    border = Border(left=border_style, right=border_style, top=border_style, bottom=border_style)

    # Function to apply styles to a sheet
    def apply_styles(sheet):
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
                except:
                    pass
            adjusted_width = (max_length + 2)
            sheet.column_dimensions[column_letter].width = adjusted_width

    # Apply styles to both sheets
    apply_styles(secrets_sheet)
    apply_styles(sam_sheet)
