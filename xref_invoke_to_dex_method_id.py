# Link invocations to their corresponding dex method ids
# Candidate for an analysis step
#
#@category Dalvik

import ghidra_utils
import dextypes
import ghidra

# TODO would this work better as a thunk reference?

def xref_invoke_to_dex_method_id(program=None):
    if program is None:
        program = currentProgram
     
    monitor.setMessage("Linking invokes to dex method ids in {}".format(program.getName()))
        
    success = False
    transaction_id = program.startTransaction("xref_invoke_to_dex_method_id analysis")
    
    try:
        dex_header = dextypes.dex_header(program=program)
        refmgr = program.getReferenceManager()
        model = ghidra.program.model.block.BasicBlockModel(program, True)
        
        funcmgr = program.getFunctionManager()
        monitor.initialize(funcmgr.getFunctionCount())
        for function in ghidra_utils.iterate(funcmgr.getFunctions(True)):
            #print("{} @ {} : {}".format(function, program, function.getEntryPoint()))
            monitor.checkCanceled()
            monitor.incrementProgress(1)
            
            visited_offsets = []
            to_visit = [model.getFirstCodeBlockContaining(function.getEntryPoint(), monitor)]
            
            while len(to_visit) > 0:
                monitor.checkCanceled()
                block = to_visit.pop()
                visited_offsets.append(block.getFirstStartAddress().getOffset())
            
                for dest in ghidra_utils.iterate(block.getDestinations(monitor)):
                    monitor.checkCanceled()
                    if dest.getFlowType().isCall():
                        #print("Call @ {} : {}".format(program, address=dest.getReferent()))
                        # invoke call site
                        insn = ghidra_utils.get_instruction_at_address(address=dest.getReferent(), program=program)
                        if "invoke" not in insn.getMnemonicString():
                            raise Exception("Unknown call insn: {} @ {}: {}".format(insn, program, insn.getAddress()))
                        # it's an invocation! find the operand for the method ref
                        method_idx = insn.getOpObjects(0)[0].getValue()
                        method = dex_header.get_method(method_idx)
                        
                        # create the reference
                        # from the insn, to the dex method id, as a data read, with an analysis source, and the op index is always 0 for an invoke
                        refmgr.addMemoryReference(insn.getAddress(), ghidra_utils.get_address(method.address), ghidra.program.model.symbol.RefType.READ, ghidra.program.model.symbol.SourceType.ANALYSIS, 0)
                        
                    else:
                        dest_offset = dest.getDestinationAddress().getOffset()
                        if dest_offset not in visited_offsets:
                            if dest_offset not in [tv.getFirstStartAddress().getOffset() for tv in to_visit]:
                                to_visit.append(dest.getDestinationBlock()) 
        success = True
    finally:
        # on exception, success will be false, so the transaction will be rolled back
        program.endTransaction(transaction_id, success)
    


def xref_invoke_to_dex_method_id_all_programs():
    for program in ghidra_utils.get_all_dex_programs(openFile=True, checkout=True):
        xref_invoke_to_dex_method_id(program=program)
        

if __name__=="__main__":
    xref_invoke_to_dex_method_id()