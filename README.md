# autoLbl
Script for auto labeling PowerPC assembly generated with doldisasm.py  

This tool assumes that you have a Ghidra symbol map of the target DOL, and a CodeWarrior link map of any game that should have symbols in common with your game.  

1. The Ghidra map is used to get information about which functions exist in the target DOL.  
1. The script then searches for mangled symbols inside the CodeWarrior map that match the functions inside the Ghidra map.  
1. If the script finds a match, and the matching Ghidra map function's code resides within the given ASM file, the script will write in a label above the assembly (unless one already exists), using the mangled symbol that it found.
