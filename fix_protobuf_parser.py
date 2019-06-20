# Find and annotate Protobuf methods
#
# This method finds all the protobuf parsers and pretties them up a little by:
# - Fixing the ProtobufOpcode datatype to make switches easier to read
#@category Protobuf

PROTOBUF_PACKAGE =  # Fill in with the ghidra syntax name of the package for protobuf classes # TODO create a heuristic to find these automatically

def get_protobuf_classes(program=None):
    if not program:
        program = currentProgram
    
    protobuf_classes = ghidra.app.util.NamespaceUtils.getNamespaces(PROTOBUF_PACKAGE, program.getGlobalNamespace(), program)[0].getSymbol()
    for clazz in program.getSymbolTable().getChildren(protobuf_classes):
        yield clazz

def get_protobuf_parser_methods(clazz):
    # Get the program this class is defined in
    program = clazz.getProgram()

    for func in program.getSymbolTable().getChildren(clazz):
        yield func

def create_or_get_opcode_enum(program=None):
    if not program:
        program = currentProgram
    enum = ghidra.program.model.data.EnumDataType('ProtobufOpcode', 1)
    enum.add('WRITEFIELDS', 0x0)
    enum.add('COMPUTESIZE', 0x1)
    enum.add('PARSEFROM', 0x2)
    enum.add('POPULATEBUILDERWITHFIELD', 0x3)
    # Default to keeping any existing type
    return program.getDataTypeManager().addDataType(enum, ghidra.program.model.data.DataTypeConflictHandler.KEEP_HANDLER)


def fixup_protobuf_parser_params(program=None):
    if not program:
        program = currentProgram

    opcode_enum = create_or_get_opcode_enum(program)

    function_list = list()

    # Gather classes
    monitor.setMessage("Gathering protobuf methods...")
    for clazz in get_protobuf_classes(program):
        for func in get_protobuf_parser_methods(clazz):
            monitor.checkCanceled()
            # Turn our symbol into a function object
            func = program.getFunctionManager().getFunction(func.getID())
            function_list.append((clazz, func))

    monitor.setMessage("Fixing method parameters")
    monitor.initialize(len(function_list))
    for clazz, func in function_list:
        monitor.incrementProgress(1)
        monitor.checkCanceled()
        if func:
            # We want to match the parser
            if 3 == func.getParameterCount():
                if isinstance(func.getParameter(1).getDataType(), ghidra.program.model.data.IntegerDataType):
                    param = func.getParameter(1)
                    param.setDataType(opcode_enum, ghidra.program.model.symbol.SourceType.USER_DEFINED)
                    param.setName('opcode', ghidra.program.model.symbol.SourceType.USER_DEFINED)
                    print("[+] Updated {}".format(func.getName(True)))



if __name__ == '__main__':
    fixup_protobuf_parser_params()
