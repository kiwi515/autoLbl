class GhidraEntry:
    def __init__(self, addr, symb, namespace):
        self.addr = addr
        self.symb = symb
        self.namespace = namespace



class MwEntry:
    def __init__(self, addr, symb, dm, src, isDm):
        self.addr = addr
        self.symb = symb
        self.dmSymb = dm
        self.src = src
        self.isDm = isDm

    def address(self):   
        return self.addr

    def symbol(self):
        return self.symb

    def demangled(self):
        return self.dmSymb

    def srcfile(self):
        return self.src

    def isDemangled(self):
        return self.isDm