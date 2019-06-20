# Add references from each get/set operation on a Java field
#
# This script itereates through ever instruction in every function
# and adds a reference to the address of the field in the field table for that dex file
#
#@category Dalvik
#@menupath Analysis.One Shot.Fix DEX field references

import dextypes
import ghidra_utils

def fixup_fields():
    for program in ghidra_utils.get_programs_in_directory(currentProgram.getDomainFile().getParent(), lambda x : ".dex" in x.getName(), openFile=True, checkout=True):
        monitor.setMessage("Processing field labels {}".format(program.getName()))
        print(program.getName())
        try:
            head = dextypes.dex_header(program)
        except KeyError:
            continue
        function_list = list(program.getFunctionManager().getFunctions(True)) #getFunctionsNoStubs(True))
        monitor.initialize(head.num_fields)
        trans = program.startTransaction("xrefing")
        for f in head.get_fields():
            monitor.incrementProgress(1)
            clsstr = f.clazz[1:-1].replace("/", "::")
            lab = program.getSymbolTable().getPrimarySymbol(f.address)
            if lab == None or not lab.getName() == clsstr + "::" + f.name.content:
                lab = program.getSymbolTable().createLabel(f.address, clsstr + "::" + f.name.content, ghidra.program.model.symbol.SourceType.USER_DEFINED)
            namespacelist = ghidra.app.util.NamespaceUtils.getNamespaces(clsstr, program.getGlobalNamespace(), program)
            if len(namespacelist) == 0:
                namespace = ghidra.app.util.NamespaceUtils.createNamespaceHierarchy(clsstr, program.getGlobalNamespace(), program, ghidra.program.model.symbol.SourceType.USER_DEFINED)
                namespace = ghidra.app.util.NamespaceUtils.convertNamespaceToClass(namespace)
            else:
                namespace = namespacelist[0]

            try:
                try:
                    lab.setNameAndNamespace(f.name.content, namespace, ghidra.program.model.symbol.SourceType.USER_DEFINED)
                except ghidra.util.exception.InvalidInputException:
                    lab.setNameAndNamespace("_"+f.name.content, namespace, ghidra.program.model.symbol.SourceType.USER_DEFINED)
            except ghidra.util.exception.DuplicateNameException:
                pass

        monitor.setMessage("Processing references {}".format(program.getName()))
        monitor.initialize(len(function_list))
        for f in function_list:
            monitor.incrementProgress(1)
            inst = program.getCodeManager().getInstructionAt(f.getEntryPoint())
            func = ghidra_utils.get_function_at_address(inst.getAddress(), program)

            while inst is not None and func is not None and func.getEntryPoint() == f.getEntryPoint():
                monitor.checkCanceled()
                op = inst.getMnemonicString()
                if 'iget' in op or 'sget' in op or 'iput' in op or 'sput' in op:
                    i = 0 
                    while not (inst.getOperandRefType(i) == ghidra.program.model.symbol.RefType.DATA and isinstance(inst.getOpObjects(i)[0], ghidra.program.model.scalar.Scalar)):
                        i = i + 1
                    label = inst.getOpObjects(i)[0].getValue()
                    if 'iget' in op or 'sget' in op:
                        reftype = ghidra.program.model.symbol.RefType.READ
                    else:
                        reftype = ghidra.program.model.symbol.RefType.WRITE
                    program.getReferenceManager().addMemoryReference(inst.getAddress(), dextypes.dex_field(head, label).address, reftype, ghidra.program.model.symbol.SourceType.USER_DEFINED, i)
                inst = inst.getNext()
                if inst is not None:
                    func = ghidra_utils.get_function_at_address(inst.getAddress(), program)
                else:
                    # If we don't have an instruction, we can't be in a function
                    func = None
        program.endTransaction(trans, True)

fixup_fields()
