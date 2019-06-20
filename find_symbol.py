# Locate a symbol from an APK's dex files
#
# This method searches for internal and external symbols
# and for namespaces that match the search term.
# This means you'll see things that use the symbol as well
# as where it's defined.
#
#
# Tick the box next to this script to enable the menu option.
#@category Dalvik
#@menupath Search.Dalvik.For symbol in APK DEX files

from ghidra_utils import get_programs_in_directory, SymbolDescriptor, get_parent_folder
from __main__ import *

def search_for_symbol(symbol_name, program):
    monitor.setMessage("Searching {}...".format(program))
    symbol_name = SymbolDescriptor(symbol_name).to_ghidra()
    for symbol in program.getSymbolTable().getSymbols(symbol_name):
        monitor.checkCanceled()
        yield symbol
    for symbol in program.getSymbolTable().getExternalSymbols(symbol_name):
        monitor.checkCanceled()
        yield symbol
    for symbol in ghidra.app.util.NamespaceUtils.getSymbols(symbol_name, program):
        yield symbol


def search_open_programs_for_symbol(symbol_name, base_program):
    directory = get_parent_folder(base_program)
    
    for program in get_programs_in_directory(directory, lambda x: '.dex' in x.getName()):
        monitor.checkCanceled()
        for symbol in search_for_symbol(symbol_name, program):
            yield symbol

if __name__ == '__main__':
    symbol_name = askString("Symbol Search", "Enter a symbol to find in this APK")
    for symbol in search_open_programs_for_symbol(symbol_name, currentProgram):
        monitor.checkCanceled()
        print("{}\t{}".format(symbol.getProgram().getDomainFile(), symbol.getName(True)))
