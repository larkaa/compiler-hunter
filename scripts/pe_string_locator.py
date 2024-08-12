import pefile
import sys
import subprocess
import shutil
from collections import defaultdict

def print_section_names(pe):
    print(f"Sections in the PE file:")
    for section in pe.sections:
        print(f"- {section.Name.decode().strip()} (Offset: 0x{section.PointerToRawData:x}, Size: 0x{section.SizeOfRawData:x})")

def find_string_offsets(pe_file_path, strings_list):
    strings_executable = shutil.which("strings")  
    if not strings_executable:
        print("Error: 'strings' command not found. Please ensure it is installed and in your system's PATH.")
        sys.exit(1)

    matched_strings = defaultdict(list)

    try:
        # Run the strings command for normal ASCII strings
        result = subprocess.run([strings_executable, "-t", "x", pe_file_path], capture_output=True, text=True)
        ascii_strings_output = result.stdout.splitlines()
        
        # No tag for ASCII strings
        for line in ascii_strings_output:
            line = line.strip()
            if line:
                offset_and_string = line.split(' ', 1)
                if len(offset_and_string) == 2:
                    offset, found_string = offset_and_string
                    found_string = found_string.strip()
                    for input_string in strings_list:
                        if input_string.lower() in found_string.lower():
                            matched_strings[found_string].append((int(offset, 16), ''))
        
        # Run the strings command for wide (UTF-16LE) encoded strings
        result = subprocess.run([strings_executable, "-t", "x", "-e", "l", pe_file_path], capture_output=True, text=True)
        wide_strings_output = result.stdout.splitlines()
        
        # Add tag for wide strings
        for line in wide_strings_output:
            line = line.strip()
            if line:
                offset_and_string = line.split(' ', 1)
                if len(offset_and_string) == 2:
                    offset, found_string = offset_and_string
                    found_string = found_string.strip()
                    for input_string in strings_list:
                        if input_string.lower() in found_string.lower():
                            matched_strings[found_string].append((int(offset, 16), 'wide'))
    
    except subprocess.CalledProcessError as e:
        print(f"Error running 'strings' command: {e}")
        sys.exit(1)

    return matched_strings

def check_string_locations(pe, matched_strings):
    sectioned_strings = defaultdict(list)
    
    for full_string, offsets in matched_strings.items():
        for offset, format_indicator in offsets:
            found = False
            for section in pe.sections:
                section_start = section.PointerToRawData
                section_end = section_start + section.SizeOfRawData
                
                if section_start <= offset < section_end:
                    sectioned_strings[section.Name.decode().strip()].append((full_string, offset, format_indicator))
                    found = True
                    break
            if not found:
                sectioned_strings["Not in any section"].append((full_string, offset, format_indicator))
    
    for section_name, strings_offsets in sectioned_strings.items():
        print(f"\nSection {section_name}:")
        for full_string, offset, format_indicator in strings_offsets:
            print(f" @offset {hex(offset)}:{format_indicator}\t'{full_string}' ")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python script_name.py <pe_file_path> <string1> [<string2> ... <stringN>]")
        sys.exit(1)
    
    pe_file_path = sys.argv[1]
    strings_list = sys.argv[2:]

    try:
        pe = pefile.PE(pe_file_path)
        
        print_section_names(pe)
        print()

        # Find string offsets in the PE file
        matched_strings = find_string_offsets(pe_file_path, strings_list)
        
        # Check the string locations within the sections
        if matched_strings:
            print("\nChecking string locations within the PE sections")
            check_string_locations(pe, matched_strings)
        else:
            print("No matching strings found.")
        
        pe.close()
        
    except Exception as e:
        print(f"Error processing {pe_file_path}: {e}")
