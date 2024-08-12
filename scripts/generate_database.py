import os
import hashlib
import sqlite3
import subprocess
import sys
import pandas as pd

database_name = 'metadata.db'

def find_pe_files(directory_path):
    # Identify all PE (*.exe) files in the given directory and its subdirectories
    pe_files = []
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            if file.lower().endswith(".exe"):
                pe_files.append(os.path.join(root, file))
    return pe_files

def connect_to_database():
    # Connect to the SQLite database
    connection = sqlite3.connect(database_name)
    return connection

def hash_file(file_path):
    # Generate a hash as unique id for each file
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as afile:
        buf = afile.read()
        hasher.update(buf)
    return hasher.hexdigest()

def initialize_database(connection):
    cursor = connection.cursor()
    
    # Create tables if they don't exist
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS Executables (
            id TEXT PRIMARY KEY,
            file_path TEXT,
            language TEXT,
            compiler TEXT,
            version TEXT
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS Strings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            executable_id TEXT,
            string_value TEXT,
            encoding TEXT,
            FOREIGN KEY (executable_id) REFERENCES Executables(id)
        )
    """)
    
    connection.commit()

def extract_metadata_from_path(file_path):
    # Extract language, compiler, and version from the file path
    path_parts = file_path.split(os.sep)
    if len(path_parts) >= 3:
        language = path_parts[-3]  # Folder containing the language
        compiler = path_parts[-2]  # Folder containing the compiler
        version = os.path.splitext(path_parts[-1])[0].split('_')[-1]  # Extract version from the file name
    else:
        language = compiler = version = None
    
    return language, compiler, version

def generate_dataset_and_initialize_db(directory_path):
    connection = connect_to_database()
    initialize_database(connection)
    cursor = connection.cursor()

    pe_files = find_pe_files(directory_path)
    
    # Add the PE files to the database
    for file_path in pe_files:
        file_hash = hash_file(file_path)
        language, compiler, version = extract_metadata_from_path(file_path)
        
        cursor.execute("""
            INSERT OR IGNORE INTO Executables (id, file_path, language, compiler, version)
            VALUES (?, ?, ?, ?, ?)
        """, (file_hash, file_path, language, compiler, version))
    
    connection.commit()
    connection.close()


def extract_metadata(connection):
    query = "SELECT id, language, compiler, version, file_path FROM Executables"
    return pd.read_sql_query(query, connection)

def extract_strings(file_path):

    #convert path name to linux-like for wsl
    wsl_file_path = subprocess.run(['wslpath', file_path], capture_output=True, text=True).stdout.strip()
    
    # Run the strings command to extract ASCII and wide strings
    result_ascii = subprocess.run(["strings", wsl_file_path], capture_output=True, text=True)
    result_wide = subprocess.run(["strings", "-e", "b", wsl_file_path], capture_output=True, text=True)
    
    
    strings_ascii = [(line.split(' ', 1)[-1].strip(), 'ascii') for line in result_ascii.stdout.splitlines()]
    strings_wide = [(line.split(' ', 1)[-1].strip(), 'wide') for line in result_wide.stdout.splitlines()]
    
    return strings_ascii + strings_wide

def analyze_unique_strings(df, level):
    grouped = df.groupby(level)
    unique_strings = grouped['string_value'].apply(lambda x: x[~x.duplicated(keep=False)])
    return unique_strings.reset_index()

def store_results(connection, table_name, df):
    df.to_sql(table_name, connection, if_exists='replace', index=False)

def perform_strings_analysis():
    connection = sqlite3.connect(database_name)
    
    # Extract metadata from database
    metadata = extract_metadata(connection)

    
    # Extract strings for each executable
    all_strings = []
    for _, row in metadata.iterrows():
        strings = extract_strings(row['file_path'])
        for string_value, encoding in strings:
            all_strings.append({
                'executable_id': row['id'],
                'language': row['language'],
                'compiler': row['compiler'],
                'version': row['version'],
                'string_value': string_value,
                'encoding': encoding
            })

    #print(all_strings)

    # Convert to DataFrame
    strings_df = pd.DataFrame(all_strings)
    
    print('dataframe')
    print(strings_df[0:10])
    
    # Debugging: Print column names to verify they exist
    print("DataFrame columns:", strings_df.columns)

    # Analyze unique strings by language
    unique_lang_strings = analyze_unique_strings(strings_df, 'language')
    store_results(connection, 'LanguageStrings', unique_lang_strings)
    
    # Analyze unique strings by compiler within each language
    unique_compiler_strings = analyze_unique_strings(strings_df, ['language', 'compiler', 'version'])
    store_results(connection, 'CompilerStrings', unique_compiler_strings)
    
    connection.close()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python script_name.py <directory_path> <mode>")
        print("Modes: 'initialize' for dataset generation, 'analyze' for strings analysis")
        sys.exit(1)
    
    directory_path = sys.argv[1]
    mode = sys.argv[2]

    if mode == 'initialize':
        generate_dataset_and_initialize_db(directory_path)
    elif mode == 'analyze':
        perform_strings_analysis()
    else:
        print("Invalid mode. Please choose 'initialize' or 'analyze'.")
