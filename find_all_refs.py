# Locates all potential references to a symbol from an APK's dex files
#
# This method searches for the same symbols as find_symbols does
# But then searches for the references to each symbol in each dex file
# It also searches for references to related symbols in interfaces and
# super classes.
#
#
# Tick the box next to this script to enable the menu option.
#@category Dalvik
#@menupath Search.Dalvik.For potential references to a symbol in APK DEX files

from ghidra_utils import get_programs_in_directory, dictify, enforce_value
import dextypes
from find_symbol import search_for_symbol


def isclazz(sym, program):
    for c in list(program.getSymbolTable().getChildren(sym)):
        if c.getName() == "__classdef__":
            return c.getAddress()
    if sym.getSymbolType() == ghidra.program.model.symbol.SymbolType.CLASS:
        return 0
    return None


def get_classdef(sym, program):
    if isinstance(sym, unicode) or isinstance(sym, str):
        clazzes = ghidra.app.util.NamespaceUtils.getSymbols(sym, program)
        if len(clazzes) > 0:
            clazz = clazzes[0]
        else:
            return None
    else:
        clazz = sym
    ret = isclazz(clazz, program)
    while ret == None and not clazz.getParentSymbol() == None:
        clazz = clazz.getParentSymbol()
        ret = isclazz(clazz, program)
    return ret, clazz

def get_supers(symbol, supers, interfaces, header, program):
    clazzdefaddr, clazzsymbol = get_classdef(symbol, program)
    if not clazzdefaddr == None and not clazzdefaddr == 0:
        clazzdef = dictify(clazzdefaddr, program)
        if not clazzdef["superClassIndex"] == 0xffffffff:
            superclazz = header.get_type(clazzdef["superClassIndex"])
            superstring = superclazz[1:-1].replace("/", "::") + "::" +  str(symbol).split("::")[-1]
            if not superstring in supers:
                supers.add(superclazz[1:-1].replace("/", "::") + "::" +  str(symbol).split("::")[-1])
                supers = get_supers(superclazz[1:-1].replace("/", "::"), supers, interfaces, header, program)
        if not clazzdef["interfacesOffset"] == 0:
            typelist = dictify(clazzdef["interfacesOffset"], program)
            for i in xrange(typelist["size"]):
                type_index = typelist["item_" + str(i)]["typeIndex"]
                typer = header.get_type(type_index)
                interfaces.add(typer[1:-1].replace("/", "::") + "::" + str(symbol).split("::")[-1])


def print_all_refs(symbol, base_program, supers=None, interfaces=None, subs=None):
    directory = base_program.getDomainFile().getParent()
    for program in get_programs_in_directory(directory, lambda x: '.dex' in x.getName()):
        monitor.checkCanceled()
        try:
            header = dextypes.dex_header(program)
        except KeyError:
            continue
        for symbol in search_for_symbol(symbol_name, program):
            monitor.checkCanceled()
            if not (symbol.getAddress() == None or symbol.getAddress().isExternalAddress() or symbol.getAddress().getOffset() == 0):
                if not supers == None:
                    get_supers(symbol, supers, interfaces, header, program)
                for ref in symbol.getProgram().getReferenceManager().getReferencesTo(symbol.getAddress()):
                    print("{}\t{}\t{}\t{}".format(symbol.getName(True), symbol.getProgram().getDomainFile(),  ref.getFromAddress(), ref.getReferenceType()))


if __name__ == '__main__':
    symbol_name = askString("Symbol Search", "Enter a symbol to find all possible references to it in this APK")
    supers = set()
    interfaces = set()
    print_all_refs(symbol_name, currentProgram, supers, interfaces)
    if len(supers) > 1:
        print("Possible superclass references:")
        for symbol_name in supers:
            if not "java.lang.Object" in symbol_name:
                print_all_refs(symbol_name, currentProgram)
    if len(interfaces) > 0:
        print("Possible interface references:")
        for symbol_name in interfaces:
            print_all_refs(symbol_name, currentProgram)
