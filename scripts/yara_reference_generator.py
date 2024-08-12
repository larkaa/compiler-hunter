import re
import pandas as pd
import os
import sqlite3

# Function to download and save files
def download_files(urls, folder):
    for url in urls:
        file_name = os.path.join(folder, url.split('/')[-1])
        response = requests.get(url)
        with open(file_name, 'w') as file:
            file.write(response.text)

def extract_yara_info(yara_content):
    source = 'avast'
    rules = re.findall(r'rule.*?{.*?meta:.*?condition:.*?}', yara_content, re.DOTALL)
    data = []
    for rule in rules:
        tool = re.search(r'tool\s*=\s*"(.*?)"', rule)
        name = re.search(r'name\s*=\s*"(.*?)"', rule)
        version = re.search(r'version\s*=\s*"(.*?)"', rule)
        
        tool = tool.group(1) if tool else ""
        name = name.group(1) if name else ""
        version = version.group(1) if version else ""
        
        # [ "Name", "Tool","Version", "Source","Rule"])
        data.append([ name, tool, version, source, rule])
    
    return data
    
    
def avast_yara_info():
    # data within:
    # https://github.com/avast/retdec/blob/master/support/yara_patterns/tools/pe/x86/compilers.yara

    # git clone https://github.com/avast/retdec.git    
    # relative_path after git clone
    directory = 'retdec/support/yara_patterns/tools/pe'

    yara_files = []
    all_data = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.yara'):
                yara_files.append(os.path.join(root, file))


    for file_path in yara_files:
        with open(file_path, 'r') as file:
            yara_content = file.read()
            data = extract_yara_info(yara_content)
            all_data.extend(data)
    
    df = pd.DataFrame(all_data, columns=[ "Name", "Tool","Version", "Source","Rule"])
    
    return df

def extract_sg_info(sg_content):
    data = []
    
    # Extract 'type' and 'name'
    init_match = re.search(r'init\("([^"]+)",\s*"([^"]+)"\);', sg_content)
    if init_match:
        sg_type = init_match.group(1)
        name = init_match.group(2)
    else:
        sg_type = ""
        name = ""
    
    # Extract version (if available) and rule (full content for simplicity)
    version_match = re.search(r'sVersion\s*=\s*"([^"]+)";', sg_content)
    version = version_match.group(1) if version_match else ""
    
    source = 'detect-it-easy'
    # [ "Name", "Tool","Version", "Source", "Rule"])
    data.append([ name, sg_type, version, source, sg_content])
    
    return data

def extract_detect_it_easy_info():
    # git clone https://github.com/horsicq/Detect-It-Easy.git
    
    sg_files = []
    all_data = []
    
    directory = 'Detect-It-Easy/db/PE'
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.sg'):
                sg_files.append(os.path.join(root, file))

    for file_path in sg_files:
        with open(file_path, 'r') as file:
            sg_content = file.read()
            data = extract_sg_info(sg_content)
            all_data.extend(data)
    
    df = pd.DataFrame(all_data, columns=[ "Name", "Tool","Version", "Source","Rule"])
    
    return df


def extract_txt_info(txt_content):
    data = []
    
    # remove comments
    cleaned_content = re.sub(r';.*', '', txt_content)
    
    # Extract sections
    sections = re.findall(r'\[([^\]]+)\]\s*signature\s*=\s*([0-9A-F\s]+)\s*ep_only\s*=\s*(true|false)', cleaned_content, re.IGNORECASE)
    source = 'pe-id'
    
    for section in sections:
        full_name = section[0]
        signature = section[1].strip()
        ep_only = section[2].lower() == 'true'
        
        # Split name to ignore everything after '->'
        if '->' in full_name:
            name_part = full_name.split('->')[0].strip()
        else:
            name_part = full_name.strip()
        
        # Initialize tool and version
        tool = ''
        version = ''
        
        # Attempt to extract tool and version from the name part
        tool_version_match = re.match(r'(.*) v(\d+\.\d+)', name_part)
        if tool_version_match:
            tool = tool_version_match.group(1).strip()
            version = tool_version_match.group(2).strip()
        else:
            tool = name_part
        
        full_section = '''name = {}\nsiganture = {}\nep_only = {}'''.format(full_name, signature, ep_only)
        #[ "Name", "Tool","Version", "Source","Rule"]
        data.append([name_part, tool, version, source, full_section])
    
    return data

def extract_peid():
    # git clone https://github.com/packing-box/peid.git
    
    file_path = './peid/src/peid/db/userdb.txt'
    with open(file_path, 'r') as file:
        data = file.read()

    all_data = extract_txt_info(data)
    df = pd.DataFrame(all_data, columns=[ "Name", "Tool","Version", "Source","Rule"])
        
    return df
    
    
def save_to_db(df, db_name='rules.db', table_name='old_interpreters'):
    # connect, create db and table
    conn = sqlite3.connect(db_name)
    df.to_sql(table_name, conn, if_exists='replace', index=False)
    
    # Close the connection
    conn.close()

# Extract data from all sources
df_yara = avast_yara_info()
df_peid = extract_peid()
df_detect_it_easy = extract_detect_it_easy_info()

# Combine all DataFrames into one
df_combined = pd.concat([df_yara, df_peid, df_detect_it_easy], ignore_index=True)
# Optionally generate a csv file
#df_combined.to_csv("combined_rules.csv", index=False)
save_to_db(df_combined)





