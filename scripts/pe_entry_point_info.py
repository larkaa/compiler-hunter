import pefile
import os
import fnmatch
import sys

def get_entry_point_bytes(file_path):
    try:
        pe = pefile.PE(file_path)
        entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        entrypoint_address = pe.get_offset_from_rva(entry_point)  # Correct offset

        with open(file_path, 'rb') as f:
            f.seek(entrypoint_address)
            entry_point_bytes = f.read(64)
            
            return entry_point_bytes, entrypoint_address
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return None, None

def generate_match_string(byte_sequences):
    match_string = []
    for i in range(len(byte_sequences[0])):
        current_byte = byte_sequences[0][i]
        if all(seq[i] == current_byte for seq in byte_sequences):
            match_string.append(f'{current_byte:02x}')
        else:
            match_string.append('??')
    return ' '.join(match_string)

if __name__ == "__main__":
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python script_name.py <directory_path> [<pattern>]")
        sys.exit(1)
    
    directory_path = sys.argv[1]
    pattern = sys.argv[2] if len(sys.argv) == 3 else '*.exe'

    if not os.path.isdir(directory_path):
        print(f"The specified path is not a directory: {directory_path}")
        sys.exit(1)

    byte_sequences = []
    exe_files = []
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            if fnmatch.fnmatch(file.lower(), pattern.lower()):
                exe_files.append(os.path.join(root, file))
                
    if not exe_files:
        print("No matching executable files found.")
        sys.exit(1)

    print("Executable files found:")
    for file in exe_files:
        print(f"- {file}")
    print()
        
    for file_path in exe_files:
        entry_point_bytes, addy = get_entry_point_bytes(file_path)
        if entry_point_bytes:
            byte_sequences.append(entry_point_bytes)
            hex_string = ' '.join(f'{byte:02x}' for byte in entry_point_bytes)
            print(f"EP Bytes @ 0x{addy:x} for {os.path.basename(file_path)} ")
            print(f"{hex_string}\n")
        else:
            print(f"Failed to read entry point for {os.path.basename(file_path)}")

    if byte_sequences:
        match_string = generate_match_string(byte_sequences)
        print(f"\nEP YARA Rule:\n{match_string}\n")