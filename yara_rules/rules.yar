import "pe"

rule AutoHotkey_Ahk2Exe_Compiler
{
    meta:
		language = "AutoHotKey"
        description = "Detects AutoHotKey executables compiled with Ahk2Exe"
    strings:
        // not universal*** $s1 = ">AUTOHOTKEY SCRIPT<" wide ascii
		$s1 = "name=\"AutoHotkey\"" 
		$s2 = "Hotkeys/hotstrings are not allowed inside functions." wide ascii
		$s3 = /<COMPILER:\sv\d\.\d{1,2}.\d{1,3}.\d{1,3}>/ 
		
		$entry_point = { e8 ?? ?? 00 00 e9 89 fe ff ff }
		
    condition:
        uint16(0) == 0x5A4D and
		$entry_point at pe.entry_point and
		$s1 and $s2 and $s3 
		and
		(
            (@s3 > pe.sections[pe.section_index(".rsrc")].raw_data_offset and
            @s3 < pe.sections[pe.section_index(".rsrc")].raw_data_offset +
            pe.sections[pe.section_index(".rsrc")].raw_data_size)
        )

		//alternative... faster?
		//and for any section in pe.sections : (
        //    section.name == ".rsrc" and
        //    $s3 in (pe.rva_to_offset(section.virtual_address)..pe.rva_to_offset(section.virtual_address + section.virtual_size))
        //)
}

rule AutoIt_Aut2Exe_Compiler
{
    meta:
        description = "Detects AutoIt executables compiled with Aut2Exe"

    strings:
		// strings for v3.3
		$s01 = "AU3!EA06" //  .exe
        $s02 = "AutoIt script files (*.au3, *.a3x)" wide // .exe
        $s03 = ">>>AUTOIT SCRIPT<<<" wide 
		$s04 = "AutoIt v3 GUI" wide
		$s05 = "Software\\AutoIt v3\\AutoIt" wide
		$s06 = "This is a third-party compiled AutoIt script."		
		
		// strings for v3.0.10.0
		$s10 = "AutoIt v3 Compiled Script" wide 
		$s11 = "<description>AutoIt 3</description>"
		$s12 = "http://www.hiddensoft.com/autoit3/compiled.html" wide
		
		
		// version number listed in 3.0.10... 
		//$version_no = {
		//00 46 00 69 00 6C 00 65 00 56 // FileV
		//00 65 00 72 00 73 00 69 00 6F 00 6E 00 00 00 00 // ersion  
		//00 ?? 00 2C 00 20 00 ?? 00 2C 00 ?? 00 ?? 00 ??// 3, 0, 100,
		//}
		
		// v3.3.16.1
		// version numbber: 0x13d00 3, 0, 100, 0
		
		

    condition:
        uint16(0) == 0x5A4D and 
		
		all of ($s0*) or all of ($s1*)
		//and 
		//for 1 of them : (
		//	@ > pe.sections[pe.section_index(".rdata")].raw_data_offset and
		//	@ < pe.sections[pe.section_index(".rdata")].raw_data_offset +
		//	pe.sections[pe.section_index(".rdata")].raw_data_size
		//)
}


rule D_DMD_Compiler
{
    meta:
		language = "D"
        description = "Detects executables that contain either the 'DMD Compiler' string or a DMD version number (e.g., DMD 2.074)"

    strings:
		// common to DMD and LDC
		$s1 = "A cycle has been detected in your program that was undetected prior to DMD" 
        $s2 = "DMD2" nocase
        $s3 = /\sDMD\s\d\.\d{0,3}/ nocase
		

    condition:
        uint16(0) == 0x5A4D and
		all of ( $s*)
}


rule D_LDC_Compiler
{
    meta:
		language = "D"
        description = "Detects executables that were generated with LDC compiler for D"

    strings:
		//below are not present in both versions...
		//$s1 = "A cycle has been detected in your program that was undetected prior to DMD" // common to DMD and LDC
        //$s2 = "DMD Compiler" nocase
		
        $s1 = "ldc.eh_msvc"
		// $s2 = /ldc2-\d\.\d{1,3}\.\d{1,3}-windows-x64\\bin/ // this is just the download folder
		$s2 = "import\\std\\stdio.d"
		$s3 = "user32.dll" wide
		$s4 = "#+3;CScs" wide
		$s5 = "!1Aa" wide
		
    condition:
        uint16(0) == 0x5A4D and 
		all of ( $s* ) 
		
		// inspired from D-I-E: section names
		and pe.sections[pe.section_index(".minfo")].name == ".minfo" 
		// not pe.sections not working...
        //and not pe.sections[pe.section_index("._deh")].name == "._deh"
}

rule Go_go_Compiler
{
    meta:
		language = "Go"
        description = "Detects executables that were generated with Go"

    strings:
		$s01 = /go\d\.\d{1,2}\.\d{1,2}/ //compiler version
		
		$s02 = " Go buildinf:" // not present in 1.10.7
		
		// EP patterns inspired from D-I-E
		$pattern_1_7_to_1_9_common = { 48 8d ?? ?? 48 8b 3c 24 48 8d 05 ?? ?? ?? ?? ff e0 cc cc cc cc cc cc cc cc }
        $pattern_1_18_plus = { e9 ?? ?? ff ff cc cc cc cc cc cc cc cc cc cc cc }
		
		// patterns below too specific
        //$pattern_1_10_to_1_14_common_1 = { e9 ?? ?? ff ff cc cc cc cc cc cc cc cc cc 51 48 8b 01 48 8b 71 10 48 8b 49 08 65 48 8b 3c }
        //$pattern_1_10_to_1_14_common_2 = { e9 ?? ?? ff ff cc cc cc cc cc cc cc cc cc 8b 5c 24 04 64 c7 05 34 00 00 00 00 00 00 00 89 }
        //$pattern_1_10_7 = {e9 8b c8 ff ff cc cc cc cc cc cc cc cc cc cc cc 51 48 8b 01 48 8b 71 10 48 8b 49 08 65 48 8b 3c}
		//$pattern_1_15_15 = {e9 7b c9 ff ff cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc}
		
    condition:
        uint16(0) == 0x5A4D and 
		any of ( $s0* ) and
		// Does ".symtab" section exist
		pe.sections[pe.section_index(".symtab")].name == ".symtab" 
		
		// EP for different versions
		and
        (
            $pattern_1_7_to_1_9_common at pe.entry_point or
            $pattern_1_18_plus at pe.entry_point 
        )
}

rule Haskell_GHC_Compiler
{
    meta:
		language = "Haskell"
        description = "Detects executables that were generated with GHC"

    strings:
		$s01 = "GHC version" // version 8.10
		//$s02 = "x86_64_unknown_mingw32" // if compiled on windows...
		
		$s10 = /GHC version.\d\.\d{1,2}\.\d{1,2}/ // version 9+ in this format
		$s11 = /name=\"ghc(_\d{1,5}){0,1}\"/
		
		$entry_point = { 48 83 ec 28 48 8b 05 ?? ?? ?? 00 c7 00 00 00 00 00 e8 }
		
    condition:
        uint16(0) == 0x5A4D and 
		$entry_point at pe.entry_point and 
		all of ($s0*) and 
		any of ($s1*)
}

rule Java_Launch4j
{
	meta:
		language = "Java"
        description = "Detects executables that were generated with Launch4j"

    strings:
		$s01 = "launch4j.log"
		// 3.50  ... version
		$s02 = {00 ?? 2E ?? ?? 00 0A 0A // 3.50
			56 65 72 73 69 6F 6E 3A // Version:
			}
		$s03 = "This application requires a Java Runtime Environment."
		$s04 = "--l4j-debug-all"

		$entry_point = {83 ec 1c c7 04 24 ?? 00 00 00 ff 15 ?? ?? 41 00 e8 ?? fb ff ff 8d 74 26 00 8d bc 27 00 00 00 00}
		
    condition:
        uint16(0) == 0x5A4D and 
		$entry_point at pe.entry_point and 
		all of ($s0*)
}


rule Javascript_pkg_compiler
{
    meta:
		language = "Javascript"
        description = "Detects executables that were generated with pkg"

    strings:
		$s1 = /process\.versions\.pkg = \'\d\.\d{1,2}\.\d{1,2}\'/
		// ex: 23d9e45   process.versions.pkg = '5.8.1';

    condition:
        uint16(0) == 0x5A4D and 
		$s1
}


rule Nim_nim_compiler
{
    meta:
		language = "Nim"
        description = "Detects executables that were generated with nim"

    strings:
		$s1 = "fatal.nim"
		$s2 = "system.nim"
		$s3 = "io.nim"
		$s4 = ".rdata$.refptr.nim_program_result"
		//$s5 = /nim-\d\.\d{1,2}.\d{1,2}_(x64|x32)/ // nim version identifier
		
		$entry_point = {55 48 89 e5 48 83 ec 30 c7 45 fc ff 00 00 00 48 8b 05 ?? ?? ?? 00 c7 00 00 00 00 00 e8 0e 00 00}
		
    condition:
        uint16(0) == 0x5A4D and 
		$entry_point at pe.entry_point and 
		all of ($s*)
}


rule Pascal_Free_Pascal_Compiler
{
    meta:
		language = "Pascal"
        description = "Detects executables that were generated with Free Pascal FPC"

    strings:
		$s01 = /FPC \d\.\d{1,2}\.\d{1,2} \[\d{4}\/\d{2}\/\d{2}\] for / // version identifier
		//FPC 3.2.2 [2021/05/15] for i386 - Win32
		//FPC 2.0.0 [2005/05/08] for i386 - Win32
		$s02 = "jjjj" wide
		
		// note: entry point signatures are specific for each version... difficult to be generic.
    condition:
        uint16(0) == 0x5A4D and 
		all of ($s0*)
}

rule Php_Bamcompiler
{
    meta:
		language = "PHP"
        description = "Detects executables that were generated with Bambalam"

    strings:
		$s01 = "BAMBALAM_GETINI.PHP" wide
		$s02 = "BAMBALAM_INIT.PHP" wide
		
		//strings not present when compressed
		//$s10 = "include 'bambalam_getini.php';"
		//$s11 = "include 'bambalam_init.php';"
		//$s12 = "phpini.bam"
		
		//entry point for standard bam files
		$entry_point = {55 8b ec 6a ff 68 ?? ?? 50 00 68 ?? ?? 4f 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 20 53 56 57 89 65 e8 83 65 fc 00 6a 01 ff 15 ?? ?? ?? 00 59 83 0d 5c ?? ?? 00 ff 83 0d 60}
		//entry point for compressed bam files
		$entry_point_compressed = {60 be 00 ?? ?? 00 8d be 00 ?? ?? ff 57 83 cd ff eb 10 90 90 90 90 90 90 8a 06 46 88 07 47 01 db 75 07 8b 1e 83 ee fc 11 db 72 ed b8 01 00 00 00 01 db 75 07 8b 1e 83 ee fc 11 db 11 c0 01 db 73}
		
    condition:
        uint16(0) == 0x5A4D and 
		all of ($s0*) and
		($entry_point at pe.entry_point or $entry_point_compressed at pe.entry_point)  
	
}

rule Powershell_ps2exe
{
    meta:
		language = "Powershell"
        description = "Detects executables that were generated with PS2EXE"

    strings:
		//first 3 strings present in many powershell scripts...
		$s01 = "<assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>"
		$s02 = "PowerShell"
		//$s03 = /\x00v\d\.\d\.\d+/ ascii //taking a long time? unspecific... removed
		
		//specific to ps2exe
		$s14 = "PS2EXE" fullword ascii nocase // sometimes as ps2exe
        $s15 = "PS2EXEApp" fullword ascii nocase
        $s16 = "PS2EXEHost" fullword ascii nocase  
        $s17 = "PS2EXEHostUI" fullword ascii nocase
        $s18 = "PS2EXEHostRawUI" fullword ascii nocase
		
		// matches all dotnet files
		$entry_point = {ff 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        uint16(0) == 0x5A4D and 
		$entry_point at pe.entry_point and
		all of ($s0*) and 
		1 of ($s1*)
}


rule Powershell_PowerShellToolsPro_Merge_Script
{
    meta:
		language = "Powershell"
        description = "Detects executables that were generated with PowerShellToolsPro Merge-script"

    strings:
		$s3 = "PowerShellToolsPro.Packager.ConsoleHost"
		$s1 = "<assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" // manifest
		$s2 = /\.NETFramework,Version=v\d\.\d{1,3}\.\d{1,3}/ ascii
		
		
    condition:
        uint16(0) == 0x5A4D and 
		all of ($s*)
}

rule Python_Pyinstaller
{
    meta:
		language = "Python"
        description = "Detects executables that were generated with Pyinstaller"

    strings:
		// python-general
		$s02 = "PySys_GetObject" 
		$s03 = "PySys_SetObject"
		$s01 = /.python\d+.dll/ ascii
		
		// specific
		$s10 = "PYINSTALLER_STRICT_UNPACK_MODE"
		$s11 = "PyInstaller"
		$s12 = "Installing PYZ"
		
		// potential
		$s20 = "pyi-runtime-tmpdir" //based on generated codes
		$s21 = "pyi-windows-manifest-filename" //based on 2020 dider stevens rule
		
		
		$entry_point = {48 83 ec 28 e8 ?? 02 00 00 48 83 c4 28 e9 6a fe ff ff cc cc cc cc cc cc cc cc cc cc cc cc cc cc 48 83 ec 28 e8 ?? ?? 00 00 85 c0 74 21 65 48 8b 04 25 30 00 00 00 48 8b 48 08 eb 05 48 3b c8 74}
		
    condition:
        uint16(0) == 0x5A4D and 
		$entry_point at pe.entry_point and
		any of ($s0*) and
        all of ($s1*) and
		any of ($s2*)
}

rule Python_Py2Exe
{
    meta:
		language = "Python"
        description = "Detects executables that were generated with Py2Exe"

    strings:
		// python-general
		$s02 = "PySys_GetObject" 
		$s03 = "PySys_SetObject"
		$s01 = /.python\d+.dll/ ascii
		
		// specific
		$s11 = "PY2EXE_VERBOSE"
		$s12 = "PYTHONSCRIPT" wide ascii
		// manifest... maybe too specific
		//$s13 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.CRT\" version=\"9.0.21022.8\" processorArchitecture=\"x86\" publicKeyToken=\"1fc8b3b9a1e18e3b\"></assemblyIdentity>"
		
		$magic_number = { 12 34 56 78 }  // py2exe magic number
		
		//entry point python 2.7
		//$entry_point_27 = {e8 ?? 03 00 00 e9 ?? fd ff ff 8b ff 55 8b ec 8b 45 08 8b 00 81 38 63 73 6d e0 75 2a 83 78 10 03 75 24 8b 40 14 3d 20 05 93 19 74 15 3d 21 05 93 19 74 0e 3d 22 05 93 19 74 07 3d 00 40 99 01 75}
		//entry point python 3.10
		//$entry_point310 = {48 83 ec 28 e8 d7 03 00 00 48 83 c4 28 e9 72 fe ff ff cc cc 40 53 48 83 ec 20 48 8b d9 33 c9 ff 15 ?? ?? 00 00 48 8b cb ff 15 ?? ?? 00 00 ff 15 ?? ?? 00 00 48 8b c8 ba 09 04 00 c0 48 83 c4 20}

		
    condition:
        uint16(0) == 0x5A4D and 
		any of ($s0*) and
        all of ($s1*) and 
		
		for any i in (0..pe.number_of_resources - 1):
            (
                // Check if the magic number exists within the resource section
                $magic_number in (pe.resources[i].offset..pe.resources[i].offset + pe.resources[i].length)
            )
}



rule Python_Nuitka
{
    meta:
		language = "Python"
        description = "Detects executables that were generated with Nuitka"

    strings:
		// no generic python strings because
		// nuitka translates to c then exe.

		// always present?
		$s10 = "NUITKA_ONEFILE_PARENT"
		
		// not always present
		$s20 = "NUITKA_ONEFILE_BINARY"

		$entry_point = {48 83 ec 28 e8 5b 02 00 00 48 83 c4 28 e9 72 fe ff ff cc cc 48 83 ec 28 e8 9f 07 00 00 85 c0 74 21 65 48 8b 04 25 30 00 00 00 48 8b 48 08 eb 05 48 3b c8 74 14 33 c0 f0 48 0f b1 0d ?? ?? 02 00}
		
    condition:
        uint16(0) == 0x5A4D and 
		$entry_point at pe.entry_point and
        (all of ($s1*) or ($s10 and $s20))
}

rule Registry_Reg2Exe
{
    meta:
		language = "Windows Registry"
        description = "Detects executables that were generated with Reg2Exe"

    strings:
		$s01 = /R\d\dreg2exepath/ // eg: R22reg2exepath
		$s02 = "Copyright 2001-2006 by Jan Vorel" wide //maybe add regex to years...
		$s03 = "Reg2exe 'converter'" wide
		
		// identify file version:
		// FileVersion ..... 2.25 (wide)
		$s04 = { 
		    46 00 69 00 6C 00 65 00 //File
			56 00 65 00 72 00 73 00 69 00 6F 00 6E 00 //Version
			00 00 00 00 ?? 00 2E 00 ?? 00 ?? 00  // 00s then 2.25 (ex)
		}
		
		// to double check if this is generic...
		// $s02 = "publicKeyToken=\"6595b64144ccf1df\""
		
    condition:
        uint16(0) == 0x5A4D and 
        all of ($s0*) 
}


rule Ruby_Ocra_forks
{
    meta:
		language = "Ruby"
        description = "Detects executables that were generated with Ocra, ocran, or aibika"

    strings:
		$s01 = /(OCRA|OCRAN|AIBIKA)_EXECUTABLE/
		$s02 = /.(ocra|ocran|aibika)-delete-me/
		$s03 = /(ocra|ocran|aibika)stub/
		//$s01 = "OCRA_EXECUTABLE" 
		//$s02 = ".ocra-delete-me"  
		//$s03 = "ocrastub" 
		
		$entry_point_aibika = {48 83 ec 28 48 8b 05 e5 74 00 00 c7 00 00 00 00 00 e8 7a fd ff ff 90 90 48 83 c4 28 c3 0f 1f 00 48 83 ec 28 e8 d7 4d 00 00 48 83 f8 01 19 c0 48 83 c4 28 c3 90 90 90 90 90 90 90 90 90 90 90 90}
		
		$entry_point_ocran = {48 83 ec 28 48 8b 05 a5 74 00 00 c7 00 00 00 00 00 e8 7a fd ff ff 90 90 48 83 c4 28 c3 0f 1f 00 48 83 ec 28 e8 ?? 4d 00 00 48 83 f8 01 19 c0 48 83 c4 28 c3 90 90 90 90 90 90 90 90 90 90 90 90}
		
		$entry_point_ocra = {83 ec 1c c7 04 24 01 00 00 00 ff 15 80 d2 40 00 e8 bb fe ff ff 8d 74 26 00 8d bc 27 00 00 00 00 83 ec 1c c7 04 24 02 00 00 00 ff 15 80 d2 40 00 e8 9b fe ff ff 8d 74 26 00 8d bc 27 00 00 00 00}
				
    condition:
        uint16(0) == 0x5A4D and 
        all of ($s0*) and
		($entry_point_aibika at pe.entry_point or 
		$entry_point_ocran at pe.entry_point or 
		$entry_point_ocra at pe.entry_point)
		
}

rule Rust_rustc
{
    meta:
		language = "Rust"
        description = "Detects executables that were generated with Rustc"

    strings:
		$s01 = "Local\\RustBacktraceMutex"
		
		// rustc github commit version number
		$rust_commit = /\/rustc\/[0-9a-f]{40}\\(library|src)/ 
		
		$entry_point = {48 83 ec 28 e8 f3 02 00 00 48 83 c4 28 e9 72 fe ff ff cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc 66 66 0f 1f 84 00 00 00 00 00 48 83 ec 10 4c 89 14 24 4c 89 5c 24 08 4d 33 db}
				
    condition:
        uint16(0) == 0x5A4D and 
		$entry_point at pe.entry_point and
        $rust_commit and
		all of ($s0*)		
}



rule Swift_Swiftc
{
    meta:
        language = "Swift"
        description = "Detects executables that were generated with Swiftc"
		
	strings:
		$s01 = "swiftCore.dll"
		
		$entry_point = {48 83 ec 28 e8 5b 02 00 00 48 83 c4 28 e9 72 fe ff ff cc cc 48 83 ec 28 e8 a7 07 00 00 85 c0 74 21 65 48 8b 04 25 30 00 00 00 48 8b 48 08 eb 05 48 3b c8 74 14 33 c0 f0 48 0f b1 0d ?? 2a 00 00}
    
    condition:
		uint16(0) == 0x5A4D and 
		all of ($s0*) and 
		$entry_point at pe.entry_point and
		
		// look for section headers such as .sw5prtc
		// will this work on swift versions less than 5?
        for any i in (0..pe.number_of_sections - 1):
            (
                pe.sections[i].name matches /^\.sw5(prt|prtc|tymd|tyrf|rfst|flmd|asty|repl|reps|bltn|cptr|mpen|acfn|ratt|test|entr|hash)(\$[A-Z])?$/
            )
}


rule Bat_Advanced_Bat2Exe
{
    meta:
        language = "Bat"
        description = "Detects executables that were generated with Advanced Bat to exe converter https://www.battoexeconverter.com/"
		
	strings:
		$s01 = "VC20XC00U"
		$s02 = "COMSPEC"
		$s03 = "command.com"
		$s04 = "cmd.exe"
		$s05 = "Microsoft Visual C++ Runtime Library"
		
		$entry_point = {55 8b ec 6a ff 68 ?? ?? ?? 00 68 ?? ?? ?? 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec ?? 53 56 57 89 65 e8 }
		
    
	condition:
        uint16(0) == 0x5A4D and
		all of them and
		$entry_point at pe.entry_point and
		
        for any section in pe.sections : (
            (section.name == ".rdata" and
                $s02 in (section.virtual_address .. section.virtual_address + section.virtual_size)
            )
        )
	//alternative: search for specific addresses
	//condition:
	//	uint16(0) == 0x5A4D and 
	//	($s02 at 0x10130) and
	//	($s03 at 0x10120) and
	//	($s04 at 0x10118) and
	//	($s05 at 0x104c4) and
	//	and $s01
	
}

rule Bat_Advanced_Bat2exe_by_IslamAdel
{
    meta:
        language = "Bat"
        description = "Detects executables that were generated with Bat2exe converter https://github.com/islamadel/bat2exe/releases"
		
	strings:
		
		$s01 = "GenuineIntelAuthenticAMDCentaurHauls" ascii
		$s02 = "Created by BAT2EXE.net" wide
		$s03 = "CompanyName" wide
		$s04 = "040904b0" wide nocase
		// also possible: $s05 = "7zS2.sfx" wide
		
		$s10 = "Islam Adel" wide //author signed in 1.8 
		$s11 = "Igor Pavlov" wide //author changed 2.1
		
		$entry_point = {55 8b ec 6a ff 68 ?? ?? ?? 00 68 ?? ?? ?? 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 68 53 56 57 89 65 e8 33 db 89 5d fc 6a 02 ff 15 }
		
    condition:
		uint16(0) == 0x5A4D and 
		$entry_point at pe.entry_point and
		all of ($s0*) and
		any of ($s1*) 

}

// bat to exe converter 3.2
rule Bat_Advanced_Bat_to_exe_converter_64bit
{
    meta:
        language = "Bat"
        description = "Detects executables that were generated with Bat-to-exe converter https://github.com/l-urk/Bat-To-Exe-Converter-64-Bit"
		
	strings:
		
		$s01 = /inflate \d\.\d\.\d{1,2} Copyright 1995-2017 Mark Adler/
		// inflate 1.2.11 Copyright 1995-2017 Mark Adler
		$s02 = "2147483648" wide
		$s03 = "7EB7EC5321E772FD8D4ABBDCBF504AD3" wide
		$s04 = "14FA2461DDB8C34A6E85810FE36C8D4E49F45CC2" wide
		$s05 = "25912C78C5E02CBD42B1CAA5C815A105" wide

		//try to find another version to verify s02-s04...
		
    condition:
		uint16(0) == 0x5A4D and 
		all of ($s0*) 
}

// vbnet
rule VB_Visual_Basic_Compiler
{
    meta:
        language = "VB.net"
        description = "Detects executables that were generated using VB vbc"
		
	strings:
		$s01 = "Microsoft.VisualBasic"
		$s02 = "Microsoft.VisualBasic.ApplicationServices" 
		$s03 = "Microsoft.VisualBasic.Devices" 
		$s04 = "Microsoft.VisualBasic.CompilerServices" 
		
		$s10 = "vbc_v.exe"
		$s11 = /vbc_v\d{1,2}_typex64.exe/
		
		// version number as: v4.0.30319
		// all strings in .text

		$entry_point = {ff 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00}
		
    condition:
		uint16(0) == 0x5A4D and 
		$entry_point at pe.entry_point and
		all of ($s0*) and
		any of ($s1*)
		
		// alternative, set exact addresses?:
		// 0x987 Microsoft.VisualBasic
		// 0x9f7 Microsoft.VisualBasic.ApplicationServices
		// 0xa37 Microsoft.VisualBasic.Devices
		// 0xc56 Microsoft.VisualBasic.CompilerServices
}

rule VB_Visual_DotNet_Compiler
{
    meta:
        language = "VB.net"
        description = "Detects executables that were generated using VB dotnet compiler"
		
	strings:
		// .NET Version: 7.0.1123.42427 wide
		$s01 = {
		00 2E 00 4E 00 45 00 54 // .NET
		00 20 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E // Version
		00 3A 00 20 00 00 00 00 00 ?? 00 2E 00 ?? 00 2E 00 ?? 00 ?? 00 // :...7.0.11..
		} 
		$s02 = "Microsoft Corporation. All rights reserved." wide
		$s03 = "Microsoft-Windows-DotNETRuntime" wide
		$s04 = "Usage: dotnet [host-options] [path-to-application]" wide
		
		$s10 = "This package provides a low-level .NET (ECMA-335) metadata reader and writer." wide
		
		$entry_point = {48 83 ec 28 e8 ?? ?? 00 00 48 83 c4 28 e9 6a fe ff ff cc cc }
		
    condition:
		uint16(0) == 0x5A4D and 
		$entry_point at pe.entry_point and
		all of them and
		
		// most strings found in rdata
		(
			pe.sections[pe.section_index(".rdata")].raw_data_offset != 0 and
			
			$s01 in (pe.sections[pe.section_index(".rdata")].raw_data_offset .. pe.sections[pe.section_index(".rdata")].raw_data_offset + pe.sections[pe.section_index(".rdata")].raw_data_size) and
			
			$s02 in (pe.sections[pe.section_index(".rsrc")].raw_data_offset .. pe.sections[pe.section_index(".rsrc")].raw_data_offset + pe.sections[pe.section_index(".rsrc")].raw_data_size) and
			
			$s03 in (pe.sections[pe.section_index(".rdata")].raw_data_offset .. pe.sections[pe.section_index(".rdata")].raw_data_offset + pe.sections[pe.section_index(".rdata")].raw_data_size) and
			
			$s04 in (pe.sections[pe.section_index(".rdata")].raw_data_offset .. pe.sections[pe.section_index(".rdata")].raw_data_offset + pe.sections[pe.section_index(".rdata")].raw_data_size)
		)
}


// fsharp same as VB_Visual_DotNet_Compiler
rule Fsharp_dotnet
{
	meta:
        language = "F#"
        description = "Detects executables that were generated using F# dotnet compiler"
		
	strings:
		$s01 = "This function is a primitive library routine used by optimized F# code and should not be used directly"
		$s02 = "F#-LINQ"
		
		// .NET Version: 7.0.1123.42427 wide
		$s03 = {
		00 2E 00 4E 00 45 00 54 // .NET
		00 20 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E // Version
		00 3A 00 20 00 00 00 00 00 ?? 00 2E 00 ?? 00 2E 00 ?? 00 ?? 00 // :...7.0.11..
		} 
		$s04 = "Microsoft Corporation. All rights reserved." wide
		$s05 = "Microsoft-Windows-DotNETRuntime" wide
		$s06 = "Usage: dotnet [host-options] [path-to-application]" wide
		
		
		$s07 = "This package provides a low-level .NET (ECMA-335) metadata reader and writer." wide
		
		$entry_point = {48 83 ec 28 e8 ?? ?? 00 00 48 83 c4 28 e9 6a fe ff ff cc cc } // matches any dotnet...
		
    condition:
		uint16(0) == 0x5A4D and 
		$entry_point at pe.entry_point and
		all of them


}


rule Java_jpackage
{
	meta:
        language = "Java"
        description = "Detects executables that were generated using Jpackage"
		
	strings:
		$s01 = "jpackageapplauncherw.exe"
		$s02 = "jpackageapplauncherw.exe" wide
		
		// can identify version with:
		// name="jpackageapplauncherw.exe" version="17.0.8.0" processorArchitecture="X86" type="win32">

		$entry_point = {48 83 ec 28 e8 1b 04 00 00 48 83 c4 28 e9 7a fe ff ff cc cc 48 89 5c 24 10 48 89 74 24 18 57 48 83 ec 10 33 c0 33 c9 0f a2 44 8b c1 45 33 db 44 8b d2 41 81 f0 6e 74 65 6c 41 81 f2 69 6e 65 49}
		
    condition:
		uint16(0) == 0x5A4D and 
		$entry_point at pe.entry_point and
		all of them

}