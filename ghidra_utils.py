# Utility functions for working with Ghidra
#
#

# get ghidra api - note: the state and related variables (currentAddress, etc) will
# be stuck at what they were when this script was first imported. Use the getState()
# method to get an updated state when required, and query the address from that
from __main__ import *

from collections import OrderedDict

import ghidra


class SymbolDescriptor(object):
    """ Handle taking descriptors as ghidra or java notation """
    namespace = list()
    class_name = ""
    original_notation = ""
    field_or_method = None

    def __init__(self, notation):

        if notation[0] == 'L' and ';' in notation and '::' not in notation:
            java_notation = notation
            # Ljava/lang/Object;(optional .field/.method)
            namespace_and_class = None
            if notation[-1] != ";":  # not just a class
                namespace_and_class, self.field_or_method = notation.split(";")
                namespace_and_class = namespace_and_class[1:]
                # remove dot from start of field or method if present
                if "." == self.field_or_method[0]:
                    self.field_or_method = self.field_or_method[1:]
            else:
                namespace_and_class = java_notation[1:-1]

            self.namespace = namespace_and_class.split('/')[:-1]
            self.class_name = namespace_and_class.split('/')[-1]

            self.original_notation = java_notation
        elif '::' in notation and '/' not in notation:
            ghidra_notation = notation
            # "java::lang::Object"(::optional method/field)
            self.namespace = ghidra_notation.split('::')[:-1]
            # note: may not be the actual class, just the last element (e.g., could be a method name) - can't tell without further checks
            self.class_name = ghidra_notation.split('::')[-1]
            self.original_notation = ghidra_notation
        elif '::' not in notation and '/' not in notation and "." in notation:
            self.original_notation = notation
            # human style java
            if ":" in notation:
                namespace_and_class, self.field_or_method = notation.split(":")
            else:
                namespace_and_class = notation
                
            self.namespace = notation.split('.')[:-1]
            self.class_name = notation.split('.')[-1]
        
        elif '::' not in notation and '/' not in notation:
            # no class delimiters, we're just looking for like a method name or something
            self.namespace = []
            self.class_name = notation
            self.original_notation = notation  # doesn't matter
        else:
            raise Exception("{} is in an unknown notation".format(notation))

    def to_java(self):
        java_string = 'L{}/{};'.format('/'.join(self.namespace),
                                       self.class_name)
        if self.field_or_method is not None:
            java_string += "." + self.field_or_method

        return java_string
        
    def to_human_java(self):
        java_string = '{}.{}'.format('.'.join(self.namespace),
                                       self.class_name)
        if self.field_or_method is not None:
            java_string += ":" + self.field_or_method

        return java_string

    def to_ghidra(self):
        output = '::'.join(self.namespace + [self.class_name])
        if self.field_or_method is not None:
            output += "::" + self.field_or_method

        return output

    def __str__(self):
        return self.original_notation


def iterate(ghidra_iterator):
    while ghidra_iterator.hasNext():
        yield ghidra_iterator.next()


def get_address(address=None, program=None):
    """ 
    Take an integer/string address and turn it into a ghidra address
    If not address provided, get the current address
    """
    if address is None:
        if program is not None:
            if program != getState().getCurrentProgram():
                raise Exception(
                    "Using current address, but have specified not current program")
        return getState().getCurrentAddress()

    if isinstance(address, ghidra.program.model.address.GenericAddress):
        # already done, no need to fix
        return address

    if program is None:
        program = getState().getCurrentProgram()

    if not isinstance(address, str) and not isinstance(address, unicode):
        address = hex(address)
        if address.endswith("L"):
            address = address[:-1]

    return program.getAddressFactory().getAddress(address)


def get_basic_block_at_address(address=None, program=None, monitor=None, external=False):
    """ Return the basic block containing the address 

        If external is True, the basic block model will include external references
    """
    address = get_address(address=address, program=program)

    if program is None:
        program = getState().getCurrentProgram()

    model = ghidra.program.model.block.BasicBlockModel(program, external)
    block = model.getFirstCodeBlockContaining(address, monitor)

    return block


def get_basic_block():
    """ Get the current basic block """
    return get_basic_block_at_address()


def get_instruction_at_address(address=None, program=None):
    """ Get the instruction at the specified address"""
    if program is None:
        program = getState().getCurrentProgram()

    address = get_address(address=address, program=program)

    return program.getListing().getInstructionAt(address)


def get_instruction():
    """ Get the current instruction """
    return get_instruction_at_address()


def get_function_at_address(address=None, program=None):
    """ Return the function containing the address """
    if program is None:
        program = getState().getCurrentProgram()

    address = get_address(address=address, program=program)

    function = program.getListing().getFunctionContaining(address)
    if function is None:
        # there's a bug in ghidra atm such that packed switch statements aren't treated as part of a function. try the function before the address
        # get a function iterator, operating in reverse from the address - first function should be the one we want
        function_it = program.getListing().getFunctions(address, False)
        if function_it.hasNext():
            function = function_it.next()

    return function


def get_function():
    """ Get the current function """
    return get_function_at_address()


def get_nx_graph(address=None, program=None, monitor=None):
    """ Builds a networkx graph for the function containing the address """

    try:
        import networkx as nx
    except ImportError:
        raise NotImplementedError("networkx is not installed")

    if monitor is None:
        monitor = getMonitor()

    address = get_function_at_address(
        address=address, program=program).getEntryPoint()

    graph = nx.DiGraph()

    entry_block = get_basic_block_at_address(address=address, program=program)
    # always add the entry node, might be a single block function with no edges
    graph.add_node(address.getOffset())

    visited_edge_list = []
    visit_edge_list = [ref for ref in iterate(
        entry_block.getDestinations(monitor))]

    while len(visit_edge_list) > 0:
        ref = visit_edge_list.pop()
        visited_edge_list.append(str(ref))

        # only within function bounds, so no calls
        if ref.getFlowType().isJump() or ref.getFlowType().isFallthrough():
            graph.add_edge(ref.getSourceAddress().getOffset(),
                           ref.getDestinationAddress().getOffset(), ref=ref)

            dest_block = get_basic_block_at_address(
                address=ref.getDestinationAddress(), program=program)
            new_edge_list = [ref for ref in iterate(
                dest_block.getDestinations(monitor))]

            for new_edge in new_edge_list:
                # need to use string representations, because we get different java ref objects each time
                if str(new_edge) not in visited_edge_list and str(new_edge) not in [str(ref) for ref in visit_edge_list]:
                    visit_edge_list.append(new_edge)

    return graph


def dictify(struct, program=None):
    """
    Take a component/data object/address and build a dict of its fields
    """
    # scalar becomes long
    if isinstance(struct, ghidra.program.model.scalar.Scalar):
        struct = struct.getValue()

    if program is None:
        program = getState().getCurrentProgram()

    # long/int becomes address
    if isinstance(struct, int) or isinstance(struct, long):
        struct = get_address(struct, program=program)

    # address becomes data
    if isinstance(struct, ghidra.program.model.address.GenericAddress):
        # note: we use listing.getDataAt to ensure we're querying the right program
        struct = program.getListing().getDataAt(struct)

    ret = OrderedDict()
    i = 0
    while i < struct.getNumComponents():
        value = None
        if struct.getComponent(i).isArray():
            value = struct.getComponent(i).getBytes()
        elif struct.getComponent(i).isStructure():
            value = dictify(struct.getComponent(i), program=program)
        else:
            value = struct.getComponent(i).getValue()
            if isinstance(value, ghidra.program.model.scalar.Scalar):
                # turn Scalars into numbers straight up
                value = value.getValue()

        ret[struct.getComponent(i).getFieldName()] = value
        i += 1
    return ret


def enforce_value(possible_ghidra_scalar):
    """ If a value might possibly come in as a ghidra scalar, get the actual value.
    Leaves actual values unchanged """

    if isinstance(possible_ghidra_scalar, ghidra.program.model.scalar.Scalar):
        possible_ghidra_scalar = possible_ghidra_scalar.getValue()

    return possible_ghidra_scalar


def enforce_raw_address(possible_ghidra_address):
    """ If a value might possibly come in as a ghidra address, get the actual address.
    Leaves actual addresses unchanged """

    if isinstance(possible_ghidra_address, ghidra.program.model.address.GenericAddress):
        possible_ghidra_address = possible_ghidra_address.getOffset()

    return possible_ghidra_address


def decompile_function(function, monitor=None):
    decomp = ghidra.app.decompiler.DecompInterface()
    decomp.setOptions(ghidra.app.decompiler.DecompileOptions())
    decomp.setSimplificationStyle("normalize")
    decomp.openProgram(function.getProgram())
    if monitor:
        monitor.setMessage("Decompiling {}".format(str(function)))
    result = decomp.decompileFunction(function, 30, monitor)
    return result


def filter_domain_files(root, filter_func=None, checkout=False):
    """ Given a domain folder object, pass files to filter_func
    and yield them if filter_func returns True, skip if it returns
    False
    Check the file out first if checkout specified, and if we need to
    """

    # Default filter returns everything
    if filter_func is None:
        def filter_func(x): return True

    for folder in root.getFolders():
        for f in filter_domain_files(folder, filter_func):
            yield f
    for f in root.getFiles():
        if filter_func(f):
            monitor.checkCanceled()
            if checkout:
                if not f.isCheckedOut():
                    # note: only need to check the result if we specify True for exclusive checkout
                    f.checkout(False, monitor)
            yield f

# hold onto programs
PROGRAM_CACHE = dict()            
def get_programs_in_directory(directory, filter_func=None, openFile=False, checkout=False):
    """ Given a Project Directory, yield program objects for all
    programs matched by filter_func, or all programs if filter
    is None

    Open the program if openFile=True
    """
    if filter_func is None:
        def filter_func(x): return True

    for f in filter_domain_files(directory, filter_func, checkout=checkout):
        f_name = f.getPathname() 
        if f_name not in PROGRAM_CACHE:
            monitor.checkCanceled()
            consumer = java.lang.Object()
            PROGRAM_CACHE[f_name] = f.getDomainObject(consumer, True, False, monitor)
        
        program = PROGRAM_CACHE[f_name]
        if openFile:
            openProgram(program)
                
        yield program


def get_parent_folder(program=None):
    """ Get the parent folder for a program. This is easy to do with program.getDomainFile().getParent(), 
    but that only works if the program is checked out. This works for everything """
    if program is None:
        program = getState().getCurrentProgram()
    dirpath = program.getDomainFile().getPathname().rsplit(
        "/", 1)[0]  # drop the program name, only keep the directory
    if len(dirpath) == 0:
        # only one level - this will be the same as the root dir
        dirpath = "/"
    directory = getState().getProject().getProjectData().getFolder(dirpath)

    return directory


def get_all_dex_programs(openFile=False, checkout=False, sameDirectory=True, program=None):
    """ Wrapper around get_programs_in_directory, to easily get all the dex file program 

    If sameDirectory is true, will only get programs in the same directory (and sub dirs) as the current program (or program passed in) - otherwise, will use root dir and get everything.
    """
    directory = None
    if sameDirectory:
        directory = get_parent_folder(program)
    else:
        directory = getState().getProject().getProjectData().getRootFolder()

    return get_programs_in_directory(directory, filter_func=lambda x: '.dex' in x.getName(), openFile=openFile, checkout=checkout)


def get_flat(program):
    """ Return the FlatAPI for a given program """
    return ghidra.program.flatapi.FlatProgramAPI(program)


def get_class_symbol(class_name, program=None):
    """ Given a full class name (either java or ghidra), return the symbol for it, or None if not present"""
    # Note: to do partial classname searches, start from list(currentProgram.getSymbolTable().getSymbolIterator("com::foo::ba*", False))
    if program is None:
        program = currentProgram

    class_name = SymbolDescriptor(class_name).to_ghidra()
    symlist = ghidra.app.util.NamespaceUtils.getSymbols(class_name, program)

    clazz = None
    if symlist:
        clazz = symlist[0]
    return clazz


def get_functions_by_name(function_name, program=None):
    """ Given a function name (e.g., "run"), return all the functions that ghidra knows about by that name
    """
    if program is None:
        program = currentProgram

    symbols = program.getSymbolTable().getSymbols(
        function_name)  # TODO include external symbols

    for symbol in symbols:
        if symbol.getSymbolType() == ghidra.program.model.symbol.SymbolType.FUNCTION:
            yield program.getFunctionManager().getFunction(symbol.getID())


def get_functions_for_class(class_symbol, function_name=None):
    """ Get the child functions from a class symbol, with an optional function name """
    child_symbols = []

    program = class_symbol.getProgram()

    if function_name is None:
        child_symbols = program.getSymbolTable().getChildren(class_symbol)
    else:
        class_namespace = ghidra.app.util.NamespaceUtils.getNamespaces(
            class_symbol.getParentNamespace(), class_symbol.getName(), program)[0]
        child_symbols = program.getSymbolTable().getSymbols(function_name, class_namespace)

    for symbol in child_symbols:
        if symbol.getSymbolType() == ghidra.program.model.symbol.SymbolType.FUNCTION:
            yield program.getFunctionManager().getFunction(symbol.getID())


def get_all_functions_for_class(class_name):
    """ Get all the functions for a class, across all the programs """
    for program in get_all_dex_programs():
        class_symbol = get_class_symbol(class_name, program=program)
        if class_symbol is not None:
            functions = get_functions_for_class(class_symbol)

            for function in functions:
                yield function


def get_references_for_function(function):
    """ Return all the references made by a function """

    address_set = function.getBody()
    program = function.getProgram()
    refmgr = program.getReferenceManager()

    for ref_src in refmgr.getReferenceSourceIterator(address_set, True):
        refs = refmgr.getReferencesFrom(ref_src)
        for ref in refs:
            yield ref
