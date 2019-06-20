# Locate a string from an APK's dex files
#
# This scripts searchs for strings in APK DEX files
# that contain the query string. It prints the program,
# address and string to the console.
#
# Tick the box next to this script to enable the menu option.
#@category Dalvik
#@menupath Search.Dalvik.For string in APK dex files

from ghidra_utils import get_flat

from ghidra_utils import get_programs_in_directory
from __main__ import *

def search_for_string(string, program, max_results=100):
    monitor.setMessage("Searching {}...".format(program))
    flat = get_flat(program)
    for addr in flat.findBytes(program.getMinAddress(), string, max_results):
        data = getDataContaining(addr)
        # We only care about strings
        if 'string_data_item' in data.getDataType().getName():
            s = b''
            for b in data.getComponentAt(1).getBytes():
                # Ghidra gives us signed bytes, so we convert them to unsigned
                s = s + chr(b & 0xff)
            # Seems that we get some odd results, check them again to make sure they are legit
            if string in s:
                yield addr, s


def search_open_programs_for_string(string, base_program, max_results=100):
    directory = base_program.getDomainFile().getParent()
    for program in get_programs_in_directory(directory, lambda x: '.dex' in x.getName(), checkout=False, openFile=True):
        monitor.checkCanceled()
        for addr, found_string in search_for_string(string, program, max_results=max_results):
            yield (program, addr, found_string)

if __name__ == '__main__':
    string = askString("String Search", "Enter a string to find in this APK")
    for program, addr, found_string in search_open_programs_for_string(string, currentProgram):
        monitor.checkCanceled()
        print("{} @ {} : {}".format(program, addr, found_string))
