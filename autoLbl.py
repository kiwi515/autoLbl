import os
import sys
import SMAP
import cwfilt # Jackoalan's MWCC Demangler (https://gist.github.com/jackoalan/a4035651f6b870136da5)
import cwfilt_1 # bwrsandman's fork of cwfilt

#################################################
#                   USAGE                       #
#                                               #
#      autoLbl.py *.S ghidraMAP linkerMAP       #
#                                               #
#################################################

def chomp(s): # removes \n from string
    return s.rstrip("\r\n")

def asm_isGlobalLbl(s):
    return s.startswith(".global")

def asm_isLbl(s):
    return s.endswith(":")

def isFunc(s):
    return not s.startswith(".") and not s.startswith("@")

def isLikelyMangled(s):
    return s.find("__") != -1

# Read contents of asm file
asm = open(os.path.join(sys.path[0], sys.argv[1]), 'r')
asm_lines = asm.readlines()

# Read contents of Ghidra map
gMap = open(os.path.join(sys.path[0], sys.argv[2]), 'r')
gMap_lines = gMap.readlines()

# Read contents of linker (MWCC) map
mwMap = open(os.path.join(sys.path[0], sys.argv[3]), 'r')
mwMap_lines = mwMap.readlines()

# Parse Ghidra map contents (Ghidra.py)
GEntries = []
for i in gMap_lines:
    #  80035070 000028 80035070  4 MyFunc 	MyClass
    # nameEnd =                          ^
    nameEnd = i[30:].find(' ')

    GEntries.append(SMAP.Entry(i[2:10], i[30:nameEnd+30], " ", chomp(i[i.rfind('\t')+1:]), True))

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
                print("[cwfilt] Failed to demangle " + symb)

    MWEntries.append(SMAP.Entry("UNUSED", symb, dmsymb, src, isDemangled))

# Search for functions in ASM
inASMcount = 0
identifyCt = 0
matches = []
for i in GEntries:
    match = " "
    matches.clear()
    for j in range(0, len(asm_lines)):
        if asm_lines[j].find(i.address().upper()) == 3:
            inASMcount = inASMcount + 1
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
                    if i.srcfile() == namespace:
                        # if Ghidra map entry's function name == value in var funcName
                        if i.symbol() == funcName:
                            identifyCt = identifyCt + 1
                            matches.append(k.symbol())
                #else:
                #    # Mangled symbol match. Unlikely to be correct, but the user is informed of it anyways.
                #    if k.symbol()[0:k.symbol().find("__")] == i.symbol() and k.srcfile().find(i.srcfile()) != -1:
                #        print("*POSSIBLE* match found: " + k.symbol() + ' -> ' + i.symbol() + " (" + i.address() + ")")

    # Print match if there is only one
    if len(matches) == 1:
        print(i.srcfile() + "::" + i.symbol() + " -> " + matches[0])
        match = k.symbol()
    # Print all matches if there are multiple
    if len(matches) != 0 and len(matches) > 1:
        print(len(matches) + " matches found: ")
        for l in range(0, len(matches)):
            print((l+1) + ". " + matches[l])
        
        # User chooses match
        num = -1
        while num > 0 and num < len(matches):
            print("Enter the number of the match you want to use: ")
            num = input()
        match = matches[num]
        print("Chosen match: " + match)*

print("\nIdentified " + str(identifyCt) + "/" + str(inASMcount) + " functions inside " + sys.argv[1])