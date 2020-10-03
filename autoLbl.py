########################################################
#               ***** SCRIPT USAGE *****               #
#                                                      #
#      autoLbl.py *.S ghidraMAP linkerMAP asm_dir      #
#                                                      #
########################################################

import os
import sys
import SMAP
import cwfilt # Jackoalan's MWCC Demangler (https://gist.github.com/jackoalan/a4035651f6b870136da5)
import cwfilt_1 # bwrsandman's fork of cwfilt
from postprocess import format, decodeformat # OGWS edit of Riidefi's postprocess script https://github.com/doldecomp/ogws/blob/master/tools/postprocess.py

############################################################
# colorama is used so ANSI control codes work with Windows #
############################################################
color = True
try:
    from colorama import init, deinit, Fore, Style
except ModuleNotFoundError:
    print("Module colorama not found. Attempting to install through pip.....")
    os.system('{} -m pip install -U '.format(sys.executable) + "colorama -q")
    try:
        from colorama import init, deinit, Fore, Style
    except ModuleNotFoundError:
        print("Module not imported successfully. This is not a problem, however, text coloring will not be used.")
        color = False
if color: init()



#######################################################################
#                                                                     #
#                        ***** FUNCTIONS *****                        #
#                                                                     #
#######################################################################

######################################################
# chomp(String s)                                    #
# Chomps newline (just like how Perl's chomp works). #
######################################################
def chomp(s):
    return s.rstrip("\r\n")

#############################################
# isFunc(String symbol)                     #
# Stops most compiler-generated labels from #
# attempted demangling (always will fail).  #
#############################################
def isFunc(s):
    return not s.startswith(".") and not s.startswith("@")

########################################
# isLikelyMangled(String symbol)       #
# Rudimentary check to see if a symbol #
# is likely mangled.                   #
########################################
def isLikelyMangled(s):
    return s.find("__") != -1

################################################################
# parseGhidraMap(string fPath)                                 #
# Opens Ghidra symbol map for read access and reads each entry #
# into a SMAP.GhidraEntry object.                              #
################################################################
def parseGhidraMap(s):
    # Read contents of Ghidra map
    gMap = open(os.path.join(sys.path[0], s), 'r')
    gMap_lines = gMap.readlines()
    # Parse Ghidra map contents (Ghidra.py)
    GEntries = []
    for i in gMap_lines:
        #  80035070 000028 80035070  4 MyFunc 	MyClass
        # nameEnd =                          ^
        nameEnd = i[30:].find(' ')
        GEntries.append(SMAP.GhidraEntry(i[2:10], i[30:nameEnd+30], chomp(i[i.rfind('\t')+1:])))
    gMap.close()
    return GEntries

################################################################
# parseMwMap(string fPath)                                     #
# Opens CodeWarrior (MetroWerks) symbol map for read access    #
# and reads each entry into a SMAP.MwEntry object.             #
################################################################
def parseMwMap(s):
    # Read contents of linker (MWCC) map
    mwMap = open(os.path.join(sys.path[0], s), 'r')
    mwMap_lines = mwMap.readlines()
    # Parse CodeWarrior link map contents
    MWEntries = []
    for i in mwMap_lines:
        isDemangled = False
        dmsymb = " "
        #  003cd94c 000088 803dbd8c 003d7f6c  4 mySymb  myLib.a myObj.o
        # symbEnd =                                   ^
        symbEnd = i[39:].find(' ')
        #  003cd94c 000088 803dbd8c 003d7f6c  4 mySymb  myLib.a myObj.o
        # symb =                               {     }
        symb = i[39:symbEnd+39] # Symbol name
        #  003cd94c 000088 803dbd8c 003d7f6c  4 mySymb  myLib.a myObj.o
        # srcStart =                                           ^
        srcStart = i.rfind(' ') # Source file string beginning, found by getting the last space char in the line
        src = chomp(i[srcStart:])
        if isFunc(symb) and isLikelyMangled(symb) == True:
            # Use the fork of cwfilt to demangle all symbols the original script fails to demangle
            try:
                dmsymb = cwfilt.demangle(symb)
                isDemangled = True
            except Exception:
                try:
                    dmsymb = cwfilt_1.demangle(symb)
                except Exception:
                    if color: print(Fore.RED + "[CWFILT] Failed to demangle " + symb + Fore.RESET)
                    else: print("[CWFILT] Failed to demangle " + symb)
        MWEntries.append(SMAP.MwEntry("UNUSED", symb, dmsymb, src, isDemangled))
    mwMap.close()
    return MWEntries

#########################################
# readAsmFile(String fPath)             #
# Split ASM file text lines into a list #
#########################################
def readAsmFile(s):
    asm = open(os.path.join(sys.path[0], s), 'r')
    asm_lines = asm.readlines()
    asm.close()
    return asm_lines

####################################################
# countFuncsInAsm(GhidraEntry[] ghi, String[] asm) #
# Count how many functions exist in the ASM file   #
# that also exist in the Ghidra map.               #
####################################################
#def countFuncsInAsm(ghi, asm):
#    c = 0
#    for i in ghi:
#        for j in asm:
#            if j.find(i.addr.upper()) == 3:
#                c +=1
#    return c

#############################################################################
# replaceStrsInFile(String fPath, String[] s1, String[] s2)                 #
# Replace all occurrences of s1[i] with s2[i] in the file located at fPath. #
#############################################################################
def replaceStrsInFile(fPath, s1, s2):
    # Open file and read it into lines
    # Then replace instances of s1 with s2 in lines
    f = open(fPath, 'r')
    fl = f.readlines()
    for i in range(0, len(fl)):
        for j in range(0, len(s1)):
            fl[i] = fl[i].replace(("func_" + s1[j]), s2[j])
            fl[i] = fl[i].replace(("lbl_" + s1[j]), s2[j])
    f.close()

    # Truncate existing file and write lines to file
    f = open(fPath, 'w')
    for i in fl:
        f.write(i)
    f.close()

#################################################################
# replaceLblsInDir_recursive(String dir, String s1, String s2)  #
# Iterate through directory dir's files and child directories   #
# to replace all occurrences of old address with new symbol     #
#################################################################
def replaceLblsInDir_recursive(dir, symbs, addrs):
    for subdir, dirs, files in os.walk(dir):
        for filename in files:
            filepath = subdir + os.sep + filename
            if file_IsAsm(filepath): 
                replaceStrsInFile(filepath, symbs, addrs)

#############################################
# file_IsAsm(String s)                      #
# Check if the given file name ends         #
# with a common PowerPC assembly extension. #
#############################################
def file_IsAsm(s):
    return s.upper().endswith(".S") or s.upper().endswith(".ASM") or s.upper().endswith(".PPC")



#######################################################################
#                                                                     #
#                        ***** MAIN BODY *****                        #
#                                                                     #
#######################################################################

# Setup file contents
asm_lines = readAsmFile(sys.argv[1])
asm_output = asm_lines
GEntries = parseGhidraMap(sys.argv[2])
MWEntries = parseMwMap(sys.argv[3])

# Search for functions in ASM
inAsmCount = 0
identifyCt = 0
matches = []
match_lines = []
match_line = 0
final_list = []
final_addr_list = []
for i in GEntries:
    addr_list = []
    match = " "
    matches.clear()
    match_lines.clear()
    for j in range(0, len(asm_lines)):
        if asm_lines[j].find(i.addr.upper()) == 3:
            inAsmCount += 1
            for k in MWEntries:
                # Demangled symbol match
                if k.isDemangled():

                    if k.symbol().startswith("__sinit_\\"):
                        funcName = k.symbol()
                        namespace = "Global"
                    else:
                        # sample::sample2::myNamespace::myFunc(void)
                        # namespaceEnd =              ^
                        namespaceEnd = k.demangled()[:k.demangled().rfind("(")].rfind("::")

                        # sample::sample2::myNamespace::myFunc(void)
                        # namespaceBeg = ^
                        namespaceBeg = k.demangled()[:namespaceEnd].rfind("::")

                        # sample::sample2::myNamespace::myFunc(void)
                        # namespace =     {          }
                        namespace = k.demangled()[namespaceBeg+2:namespaceEnd]

                        # sample::sample2::myNamespace::myFunc(void)
                        # sig =                        {           }
                        sig = k.demangled()[namespaceEnd+2:]

                        # sample::sample2::myNamespace::myFunc(void)
                        # funcName =                   {     }
                        funcName = sig[:sig.find("(")] if sig.find("(") != -1 else sig # if the function signature has no "(" somehow then funcName takes sig's value

                        if funcName == "__dt": funcName = '~' + namespace # funcName = "~MyClass" if funcName == "__dt"
                        if funcName == "__ct": funcName = namespace       # funcName = "MyClass" if funcName == "__ct"

                    # if Ghidra map entry's class/namespace == value in var namespace
                    if i.namespace == namespace:
                        # if Ghidra map entry's function name == value in var funcName
                        if i.symb == funcName:
                            matches.append(k.symbol())
                            match_lines.append(j)
                            addr_list.append(i.addr.upper())

    # Print match if there is only one
    if len(matches) == 1:
        num = 1
        if color: print(Fore.GREEN + "[MATCH] " + i.namespace + "::" + i.symb + " -> " + matches[0] + Fore.RESET)
        else: print("[MATCH] " + i.namespace + "::" + i.symb + " -> " + matches[0])
        match = matches[0]
        match_line = match_lines[0]
        identifyCt = identifyCt + 1
        final_list.append(format(match))
        final_addr_list.append(addr_list[0])
    # Print all matches if there are multiple
    if len(matches) != 0 and len(matches) > 1:
        print(Fore.YELLOW + "[MATCH] " + str(len(matches)) + " matches found for " + i.namespace + "::" + i.symb + ": ")
        for l in range(0, len(matches)):
            print('\t' + str((l+1)) + ". " + matches[l], end = '')
            try:
                print(" (" + cwfilt.demangle(matches[l]) + ")")
            except Exception:
                try:
                    print(" (" + cwfilt_1.demangle(matches[l]) + ")")
                except Exception:
                    print(Fore.RED + "(demangle failed)")

        if color: print(Fore.RESET)
        else: print(' ')
        
        # User chooses match
        num = -1
        while True:
            if color: print(Fore.YELLOW + "[INPUT] Enter the number of the match you want to use: " + Fore.RESET, end = '')
            else: print("[INPUT] Enter the number of the match you want to use: ", end = '')
            try:
                num = int(input())
            except Exception:
                if color: print(Fore.RED + "[INPUT] Invalid input entered. Try again (1-" + str(len(matches)) + "): " + Fore.RESET)
                else: print("[INPUT] Invalid input entered. Try again (1-" + str(len(matches)) + "): ")
            if num > 0 and num <= len(matches): break
        match = matches[num-1]
        identifyCt = identifyCt + 1
        if color: print(Fore.YELLOW + "[INPUT] Chosen match: " + match + Fore.RESET)
        else: print("[INPUT] Chosen match: " + match)
        match_line = match_lines[num-1]
        final_list.append(format(match))
        final_addr_list.append(addr_list[num-1])

    # No existing label
    if len(matches) != 0:
        if asm_output[match_line - 1].startswith("/*"):
            asm_output.insert(match_line, (format(match) + ":\n"))
            asm_output.insert(match_line, (".global " + format(match) + "\n"))
            # If the symbol has invalid chars that get formatted out, comment in the unformatted version for readability
            if format(match) != match: asm_output.insert(match_line, ("# " + match + '\n'))
            # Newline if necessary
            if asm_output[match_line - 1] != '\n': asm_output.insert(match_line, '\n')
        # A label exists but it is not the correct symbol (fun_*, lbl_*, etc.)
        elif asm_output[match_line - 1].find(':') != -1 and asm_output[match_line - 1].find(match) == -1:
            if asm_output[match_line - 2].startswith(".global") and asm_output[match_line - 2].find(match) == -1:
                asm_output[match_line - 1] = (format(match) + ":\n")
                asm_output[match_line - 2] = (".global " + format(match) + '\n')
                # If the symbol has invalid chars that get formatted out, comment in the unformatted version for readability
                if format(match) != match: asm_output.insert(match_line - 2, ("# " + match + '\n'))
                # Newline if necessary
                if asm_output[match_line - 3] != '\n': asm_output.insert(match_line - 2, '\n')



if color: 
    print(Fore.CYAN + "\n[STATS] Identified and labeled " + str(identifyCt) + "/" + str(inAsmCount) + " functions inside " + sys.argv[1])
    deinit()
else: print("\n[STATS] Identified " + str(identifyCt) + "/" + str(inAsmCount) + " functions inside " + sys.argv[1])

# Overwrite asm file with labeled version
print("[OUTPUT] Writing new information to " + sys.argv[1] + "....")
f = open(sys.argv[1], "w+")
for i in asm_output:
    f.write(i)
f.close()

# Update xrefs throughout project to reflect the new symbols
print("[OUTPUT] Overwriting xrefs in " + sys.argv[4] + " of old symbols with new symbols....")
replaceLblsInDir_recursive(sys.argv[4], final_addr_list, final_list)
print("[SUCCESS] Done!")

