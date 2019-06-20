# Locates all direct references to a symbol from an APK's dex files
#
# This method searches for the same symbols as find_symbols does
# But then searches for the references to each symbol in each dex file
#
#
# Tick the box next to this script to enable the menu option.
#@category Dalvik
#@menupath Search.Dalvik.For direct references to a symbol in APK DEX files

from ghidra_utils import get_programs_in_directory
from find_symbol import search_for_symbol, search_open_programs_for_symbol

if __name__ == '__main__':
    symbol_name = askString("Symbol Search", "Enter a symbol to find refences for in this APK")
    for symbol in search_open_programs_for_symbol(symbol_name, currentProgram):
        monitor.checkCanceled()
        if not (symbol.getAddress() == None or symbol.getAddress().isExternalAddress() or symbol.getAddress().getOffset() == 0):
            for ref in symbol.getProgram().getReferenceManager().getReferencesTo(symbol.getAddress()):
                print("{}\t{}\t{}\t{}".format(symbol.getName(True), symbol.getProgram().getDomainFile(),  ref.getFromAddress(), ref.getReferenceType()))

