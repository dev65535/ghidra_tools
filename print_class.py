"""  """

from ghidra_utils import dictify

def bytes_to_int(b):
    """
    Read in a byte array as varint
    """
    ret = 0
    i = 0
    while i < len(b):
        ret = ret | (((b[i]%256) & 0x7f) << 7*i)
        i += 1
    return ret

def get_tree(name):
    """
    Helper method to get data from the tree manager by name
    """
    for i in currentProgram.getTreeManager().getDefaultRootModule().getChildren():
        if i.getName() == name:
                return i.getCodeUnits()
    return None


def build_string_list():
    """
    Returns a list of addresses for each string based on their string ID
    The list isn't too large and it's much faster only iterating through all the code objects once
    """
    stritr = get_tree("strings")
    strlist = []
    for s in stritr:
        strlist.append(dictify(s)["stringDataOffset"])
    return strlist

def get_string(n, strlist):
    """
    Return the string with string_id n using the address mapping strlist
    """
    return dictify(getDataAt(currentProgram.getAddressFactory().getAddress(str(strlist[n]))))["data"]

def build_type_list(strlist):
    """
    Uses an existing mapping of string_ids to addresses to create a mapping of type_ids to addresses
    """
    typeitr = get_tree("types")
    typelist = []
    for t in typeitr:
        typelist.append(strlist[dictify(t)["descriptorIndex"].getUnsignedValue()])
    return typelist


def print_class(classname):
    """
    Print all of a classes fields and methods
    """
    clas = ghidra.app.util.NamespaceUtils.getSymbols(classname, currentProgram)
    symlist = list(currentProgram.getSymbolTable().getChildren(clas[0]))
    funclist = []
    instancelist = []
    staticlist = []
    strlist = build_string_list()
    typelist = build_type_list(strlist)
    for sym in symlist:
        func = currentProgram.getFunctionManager().getFunction(sym.getID())
        if func is not None:
            funclist.append("\t0x{}: {}".format(sym.getAddress(), func.getPrototypeString(True, False)).replace("* ", ""))
        elif sym.getName() == "__classdef__":
            clasdef = dictify(getDataAt(sym.getAddress()))
            clasdataaddr = getDataAt(currentProgram.getAddressFactory().getAddress(str(clasdef["classDataOffset"])))
            clasdata = dictify(clasdataaddr)
            # The class data datatypes in Ghidra only seem to parse the array lengths for each array so we have to parse the arrays ourselves
            curr = getDataAfter(clasdataaddr)
            for value in clasdata:
                numvals = bytes_to_int(clasdata[value])
                n = 0
                fields = get_tree("fields")
                while n < numvals:
                    if value in ["instance_fields", "static_fields"]:
                        inst_field = bytes_to_int(dictify(curr)["field_idx_diff"])
                        m = 0
                        f = None
                        while m < inst_field:
                            f = fields.next()
                            m += 1
                        field_data = dictify(f)
                        type_str = get_string(field_data["typeIndex"].getUnsignedValue(), typelist)
                        name_str = get_string(field_data["nameIndex"].getUnsignedValue(), strlist)
                        rep = "{} {};".format(type_str, name_str)
                        if value == "static_fields":
                            staticlist.append(rep)
                        else:
                            instancelist.append(rep)
                    curr = getDataAfter(curr)
                    n += 1
    print("class {} {}".format(classname, "{"))
    for i in staticlist:
        print("\tstatic {}".format(i))
    print("")
    for i in instancelist:
        print("\t{}".format(i))
    print("")
    for i in funclist:
        print(i)
    print("}")
