import pefile
import os
import fnmatch
import sys
import re

def get_bytes_at_offset(file_path, offset, length=32):
    try:
        with open(file_path, 'rb') as f:
            f.seek(offset)
            return f.read(length)
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return None

def find_common_byte_patterns(byte_sequences, check_length, entry_point_offset, min_match_size=4):
    match_string = []
    i = 0
    exact_match = True
    
    while i < len(byte_sequences[0]) and i < check_length and exact_match:
        current_byte = byte_sequences[0][i]
        
        if all(seq and seq[i] == current_byte for seq in byte_sequences) and current_byte != 0x00:
            match_string.append(f'{current_byte:02x}')
        else:
            exact_match = False
            match_string.append('??')
        i += 1

    # If exact match is found, continue checking until two bytes are different or entry point is reached
    if exact_match:
        while i < entry_point_offset:
            next_bytes = [seq[i:i+1] for seq in byte_sequences]
            if all(next_bytes[0] and next_byte == next_bytes[0] for next_byte in next_bytes) and next_bytes[0] != b'\x00':
                match_string.append(f'{next_bytes[0][0]:02x}')
                i += 1
            else:
                break

    # Skip patterns that are 00s or (??)s or combinations of those
    pattern = r'^(?:\?\?|00|\s)*$'
    if bool(re.fullmatch(pattern, ' '.join(match_string))):
        return None
    if match_string[0] == '??':
        return None

    # Check if the matched pattern is at least the minimum required size
    if len(match_string) < min_match_size:
        return None
    
    return ' '.join(match_string)



def get_section_for_offset(pe, offset):
    for section in pe.sections:
        section_start = section.PointerToRawData
        section_end = section_start + section.SizeOfRawData
        if section_start <= offset < section_end:
            return section.Name.decode().strip()
    return "Unknown"

def main(directory_path, specific_pattern=None, check_length=32):
    if not os.path.isdir(directory_path):
        print(f"The specified path is not a directory: {directory_path}")
        return

    exe_files = []

    for root, dirs, files in os.walk(directory_path):
        for file in files:
            if file.lower().endswith(".exe"):
                if specific_pattern and not fnmatch.fnmatch(file, specific_pattern):
                    continue
                exe_files.append(os.path.join(root, file))

    print("Executable files found:")
    for file in exe_files:
        print(f"- {file}")   
    print()
    
    if not exe_files:
        print("No executable files found.")
        return

    # Load the first executable to get the entry point
    try:
        pe = pefile.PE(exe_files[0])
        entry_point_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        entry_point_offset = pe.get_offset_from_rva(entry_point_rva)
        print(f"Entry Point offset: 0x{entry_point_offset:x}")
        
    except Exception as e:
        print(f"Error loading PE file: {exe_files[0]}, {e}")
        return

    common_patterns = []

    offset = 0
    while offset < entry_point_offset:  
        byte_sequences = []
        for file_path in exe_files:
            bytes_at_offset = get_bytes_at_offset(file_path, offset, check_length)
            if bytes_at_offset and bytes_at_offset[0] != 0x00:  # Skip sequences starting with 00
                byte_sequences.append(bytes_at_offset)

        if byte_sequences:
            common_pattern = find_common_byte_patterns(byte_sequences, check_length, entry_point_offset)
            if common_pattern:
                # Determine the section for this offset based on the first file
                section_name = get_section_for_offset(pe, offset)
                common_patterns.append((offset, section_name, common_pattern))
                # Continue scanning after the match ends
                offset += len(common_pattern.split(' ')) // 2  # Adjust the offset by the length of the matched pattern
            else:
                offset += check_length
        else:
            offset += check_length

    if common_patterns:
        for offset, section_name, pattern in common_patterns:
            print(f"@ offset 0x{offset:x} in section {section_name}:\n{pattern}\n")
    else:
        print("No common patterns found.")

if __name__ == "__main__":
    directory_path = sys.argv[1]
    specific_pattern = sys.argv[2] if len(sys.argv) > 2 else None
    main(directory_path, specific_pattern)
