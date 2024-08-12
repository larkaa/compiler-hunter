import "pe"

rule entry 
{
    meta:
		language = ""
        description = "checks entry point conditions"
    strings:

		//$entry_point = { e8 ?? ?? 00 00 e9 89 fe ff ff } // AutoHotkey_Ahk2Exe_Compiler OK!
		
		//$entry_point = { 48 83 ec } // ldc : too general, matches 32...
		
		// go 2 lines -- only matches go!
		//$pattern_1_7_to_1_9_common = { 48 8d ?? ?? 48 8b 3c 24 48 8d 05 ?? ?? ?? ?? ff e0 cc cc cc cc cc cc cc cc }
        //$pattern_1_18_plus = { e9 ?? ?? ff ff cc cc cc cc cc cc cc cc cc}
		
		//$entry_point = { 48 83 ec 28 48 8b 05 ?? ?? ?? 00 c7 00 00 00 00 00 e8 } // hask/ghc/ also matches ruby
		
		//$entry_point = {83 ec 1c c7 04 24 ?? 00 00 00 ff 15 ?? ?? 41 00 e8 ?? fb ff ff 8d 74 26 00 8d bc 27 00 00 00 00} // launch4j -- only matches launch4j
		
		//$entry_point = {55 48 89 e5 48 83 ec 30 c7 45 fc ff 00 00 00 48 8b 05 ?? ?? ?? 00 c7 00 00 00 00 00 e8 0e 00 00} //nim // only matches nim
		
		//$entry_point = {55 8b ec 6a ff 68 ?? ?? 50 00 68 ?? ?? 4f 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 20 53 56 57 89 65 e8 83 65 fc 00 6a 01 ff 15 ?? ?? ?? 00 59 83 0d 5c ?? ?? 00 ff 83 0d 60} // matches uncompressed bamcompile php
		
		//$entry_point = {ff 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 } // matches all dotnet
		
		//$entry_point = {48 83 ec 28 e8 ?? 02 00 00 48 83 c4 28 e9 6a fe ff ff cc cc cc cc cc cc cc cc cc cc cc cc cc cc 48 83 ec 28 e8 ?? ?? 00 00 85 c0 74 21 65 48 8b 04 25 30 00 00 00 48 8b 48 08 eb 05 48 3b c8 74} // pyinstaller specific!
		
		//$entry_point = {48 83 ec 28 e8 5b 02 00 00 48 83 c4 28 e9 72 fe ff ff cc cc 48 83 ec 28 e8 9f 07 00 00 85 c0 74 21 65 48 8b 04 25 30 00 00 00 48 8b 48 08 eb 05 48 3b c8 74 14 33 c0 f0 48 0f b1 0d ?? ?? 02 00} // nuitka OK
		
		//$entry_point = {48 83 ec 28 e8 5b 02 00 00 48 83 c4 28 e9 72 fe ff ff cc cc 48 83 ec 28 e8 a7 07 00 00 85 c0 74 21 65 48 8b 04 25 30 00 00 00 48 8b 48 08 eb 05 48 3b c8 74 14 33 c0 f0 48 0f b1 0d ?? 2a 00 00} //swiftc OK
		
		//$entry_point = {48 83 ec 28 e8 f3 02 00 00 48 83 c4 28 e9 72 fe ff ff cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc 66 66 0f 1f 84 00 00 00 00 00 48 83 ec 10 4c 89 14 24 4c 89 5c 24 08 4d 33 db} // rustc OK
		
		//$entry_point = {55 8b ec 6a ff 68 ?? ?? ?? 00 68 ?? ?? ?? 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec ?? 53 56 57 89 65 e8 } // bat2exe also matches bamcompile?
		
		// $entry_point = {48 83 ec 28 e8 ?? ?? 00 00 48 83 c4 28 e9 6a fe ff ff cc cc } //vb dotnet : matchs fsharp and pyinstaller?
		
		//$entry_point = {ff 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00} // vbc : matchs fsharp and ps2exe
		
		$entry_point = {48 83 ec 28 e8 1b 04 00 00 48 83 c4 28 e9 7a fe ff ff cc cc 48 89 5c 24 10 48 89 74 24 18 57 48 83 ec 10 33 c0 33 c9 0f a2 44 8b c1 45 33 db 44 8b d2 41 81 f0 6e 74 65 6c 41 81 f2 69 6e 65 49} // jpackage. OK!

    condition:
        uint16(0) == 0x5A4D and
		$entry_point at pe.entry_point
}