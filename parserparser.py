# Reconstruct a protocol buffer object from a protobuf parser function
#
# This script follows control flow and data flow to reconstruct
# protobuf definitions from the control flow of a protobuf parser
# function.
#
#@category Protobuf

from ghidra_utils import decompile_function, filter_domain_files
import dextypes

PROTOBUF_PACKAGE =  # Fill in with the ghidra syntax name of the package for protobuf classes # TODO create a heuristic to find these automatically
PROTOBUF_OPCODE_FUNCTION_NAME =  # Fill in with the name of the function used by protobuf to handle the WRITEFIELDS/COMPUTESIZE/PARSEFROM/POPULATEBUILDERWITHFIELD opcodes

def iter_destinations(block):
    dests = block.getDestinations(monitor)
    while dests.hasNext():
        yield dests.next()

def get_start_block_for_address(address, program):
    model = ghidra.program.model.block.SimpleBlockModel(program, True)
    block = model.getCodeBlockAt(address, monitor)
    if block is None:
        block = model.getCodeBlocksContaining(address, monitor)[0]
    return block

def get_start_block_for_function(function):
    return get_start_block_for_address(function.getEntryPoint())

def parse_error_handler(addr, program):
    dex = dextypes.dex_header(program)
    instruction = program.getCodeManager().getCodeUnitAt(addr)
    while 'const_string' not in instruction.getMnemonicString():
        monitor.checkCanceled()
        instruction = instruction.getNext()
    string = str(dex.get_string(instruction.getScalar(1).getValue()))
    field_name = string.split(' ')[-1]
    return field_name

def reconstruct_protobuf(function):
    program = function.getProgram()
    decompilation_results = decompile_function(function)
    high_function = decompilation_results.getHighFunction()
    jump_table = high_function.getJumpTables()[0]
    cases = jump_table.getCases()

    code_manager = program.getCodeManager()

    opcode_enum = program.getDataTypeManager().getDataType('/ProtobufOpcode')

    pcode_blocks = list(high_function.getBasicBlocks())
    start_block = pcode_blocks[0]

    #print(start_block)

    conditional = start_block.getStop()

    deobfuscated_fields = dict()

    # Constants are stored in constantspace.
    # See docs/languages/html/pcoderef.html
    conditional_opcode = code_manager.getCodeUnitAt(conditional).getPcode()[0].getInputs()[1].getOffset()
    if conditional_opcode == opcode_enum.getValue('WRITEFIELDS'):
        #print("Found the write fields block")
        # The first conditional should be
        write_fields_block = start_block.getTrueOut()
        #print(start_block.getStop())

        monitor.setMessage("Scanning branches for error logs...")
        current_block = write_fields_block
        try:
            next_block = write_fields_block#.getTrueOut()
        except java.lang.IndexOutOfBoundsException:
            # This happens when there is no conditional
            next_block = None
        while next_block:
            monitor.checkCanceled()
            conditional = code_manager.getCodeUnitAt(next_block.getStop()).getPcode()[0]

            if conditional.getOpcode() == ghidra.program.model.pcode.PcodeOp.INT_NOTEQUAL:
                get_object_instruction_address = code_manager.getCodeUnitAt(next_block.getStop()).getFallFrom()
                # The field reference in an iget instruction is actually just the index into the fields
                # array in the header. Ghidra represents these as Equates.
                # Equates can have xrefs and stuff too, so if we want we can rename thio
                # TODO: Does this behave well with fix_java_fields.py? Pretty sure it will as the equate should still be there
                # but if you run into problems here, it's probably that the field is now an xref to an address.
                # Should probably make this field aware proper, we'll get better results I think.
                obfuscated_name = program.getEquateTable().getEquates(get_object_instruction_address)[0]
                try:
                    error_handler = next_block.getTrueOut()
                except java.lang.IndexOutOfBoundsException:
                    # The control flow doesn't behave the way we think it should...
                    raise Exception("Control flow error!")
                    break

                field_name = parse_error_handler(next_block.getStart(), program)
                #print("{} -> {}".format(obfuscated_name, field_name))
                deobfuscated_fields[obfuscated_name] = field_name

            try:
                candidate = next_block.getFalseOut()
            except java.lang.IndexOutOfBoundsException:
                #print("Parsed all error handlers")
                break
            if candidate == next_block:
                raise Exception("Hit a loop!")
                break
            next_block = candidate
        
    model = ghidra.program.model.block.BasicBlockModel(program, True)
    #print(cases)

    proto = dict()

    for case_index, case in enumerate(cases):
        for dest in iter_destinations(get_start_block_for_address(case, program)):
            field_id = program.getCodeManager().getCodeUnitAt(dest.getSourceAddress()).getLabel()
            if field_id not in proto:
                proto[field_id] = dict()
            proto[field_id]['case'] = case
            callee = getFunctionAt(dest.getDestinationAddress())
            if callee:
                proto[field_id]['type'] = callee.getReturnType()
            for pcode_block in pcode_blocks:
                if pcode_block.contains(dest.getDestinationAddress()):
                    #print("{} : {} -> {}".format(field_id, pcode_block.getStart(), pcode_block.getStop()))
                    search_block = pcode_block
                    out = pcode_block.getFalseOut()
                    if program.getCodeManager().getCodeUnitAt(out.getStart()).getPcode()[1].getOpcode() != ghidra.program.model.pcode.PcodeOp.RETURN:
                        #print("Repeated field")
                        proto[field_id]['repeated'] = True
                        search_block = out.getTrueOut()
                        
                    #print("Searching block: {}".format(search_block))
                    iput_instruction = None
                    instruction = code_manager.getCodeUnitAt(search_block.getStart())
                    while instruction: #and search_block.contains(instruction.getAddress()):
                        if 'iput' in instruction.getMnemonicString():
                            iput_instruction = instruction
                            break
                        instruction = instruction.getNext()


                    if iput_instruction:
                        equates = program.getEquateTable().getEquates(iput_instruction.getAddress())[0]
                        proto[field_id]['obfuscated_name'] = equates
    for field in proto.itervalues():
        name = deobfuscated_fields.get(field['obfuscated_name'])
        if name:
            field['name'] = name

    print(proto)


        
def reconstruct_all():
    # TODO: Swap to the new fancy convenience methods. This one leaks memory like a sieve
    directory = currentProgram.getDomainFile().getParent()
    for domain_program in filter_domain_files(directory, lambda x: '.dex' in x.getName()):
        consumer = java.lang.Object() # This ties to the lifetime of the domain object. When it's dropped the other file is closed
        program = domain_program.getDomainObject(consumer, True, False, monitor)
        protobuf_classes = ghidra.app.util.NamespaceUtils.getNamespaces(PROTOBUF_PACKAGE, program.getGlobalNamespace(), program)[0].getSymbol()
        for clazz in currentProgram.getSymbolTable().getChildren(protobuf_classes):
            for func in program.getSymbolTable().getChildren(clazz):
                monitor.checkCanceled()
                function = program.getFunctionManager().getFunction(func.getID())
                if function and PROTOBUF_OPCODE_FUNCTION_NAME == str(func):
                    try:
                        reconstruct_protobuf(function)
                    except java.lang.IndexOutOfBoundsException as e:
                        print("SKIP: {} {}".format(func, str(e)))
reconstruct_all()
