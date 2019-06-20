"""  """

import logging
import copy

from __main__ import getMonitor
import ghidra
import ghidra_utils
import dextypes

import values
from call import Call, ParamValue

logger = logging.getLogger(__file__)
logger.setLevel(logging.WARNING)

RETURN_REG = "return"

def get_block_address(block):
    return block.getFirstStartAddress().getOffset()
    
def get_destinations(block, monitor=None):
    if monitor is None:
        monitor = getMonitor()
    return [ref.getDestinationBlock() for ref in ghidra_utils.iterate(block.getDestinations(monitor)) if not ref.getFlowType().isCall()]
    
def get_sources(block, monitor=None):
    if monitor is None:
        monitor = getMonitor()

    return [ref.getSourceBlock() for ref in ghidra_utils.iterate(block.getSources(monitor)) if not ref.getFlowType().isCall()]
    
def find_loops(address=None, program=None, monitor=None):
    """ Walk the function to find any loop edges

        Observation - loops can only have one entry (but multiple exits [break], and multiple returns [continue]. Therefore, can rely on all elements inside a loop having passed through the entry.
    
        Therefore, define a loop edge as an edge where the path from function entrypoint to the source of the edge contains the destination of the edge.
    
        Move down destination blocks from entrypoint (skipping calls), marking as visited
        Record path for each block
        For each destination edge on each block, check if dest is already in path
            If it is, it's a loop edge!
        If a destination block is already visited, don't revisit (but the destination edge will be checked)
    """
    if monitor is None:
        monitor = getMonitor()

    function = ghidra_utils.get_function_at_address(address=address, program=program)
    
    entry_block = ghidra_utils.get_basic_block_at_address(address=function.getEntryPoint(), program=program)
    
    visited_list = []
    to_visit_list = [(entry_block, [])]
    
    loops = list()
    
    while len(to_visit_list) > 0:
        visit_block, path = to_visit_list.pop()
        visit_addr = get_block_address(visit_block)
        visited_list.append(visit_addr)
        logger.debug("checking {} {}".format(visit_block.getName(), [hex(int(addr)) for addr in path]))
        
        # add this block to path
        path.append(visit_addr)
        logger.debug([hex(int(addr)) for addr in path])
        
        # get each edge from this block
        edges = get_destinations(visit_block, monitor)
        
        for edge_dest in edges:
            edge_dest_addr = get_block_address(edge_dest)
            if edge_dest_addr in path:
                # loop detected! - edge dest is the loop head, visit is the loop tail
                loops.append((edge_dest_addr, visit_addr))
                # by implication, already visited, so don't readd
            else:
                # no loop - add it if we haven't already visited
                if edge_dest_addr not in visited_list and edge_dest_addr not in [get_block_address(block) for block, ignore in to_visit_list]:
                    add = (edge_dest, copy.copy(path))
                    logger.debug("Adding {} {}".format(add[0].getName(), [hex(int(addr)) for addr in add[1]]))
                    to_visit_list.append((edge_dest, copy.copy(path)))
                 
    logger.debug(["{}<-{}".format(hex(int(loop[0])),hex(int(loop[1]))) for loop in loops])
    return loops

def get_register_or_pair(register):
    """ return a list containing either the solo register, or the pair from an operand """
    if isinstance(register, ghidra.program.model.lang.Register):
        register = str(register.getName())
    
    if "w" in register:
        # don't just split directly - might be p0:p1 instead of vXXX:vXXX+1
        # reg will give the first register, as v
        first_idx = int(register.split("w")[1])
        first = "v" + str(first_idx)
        second = "v" + str(first_idx +1)
         
        return [first, second]
    else:
        return [register]
    
def set_register_or_pair(output_dict, reg_list, value):
    """ set the register or pair (from get_register_or_pair) to value. if a pair, the first reg gets set, the second gets set to a values.WideValue to be ignored """
    if not isinstance(reg_list, list):
        reg_list = [reg_list]

    if len(reg_list) > 1:
        output_dict[reg_list[1]] = values.WideValue(reg_list[1])
        
    output_dict[reg_list[0]] = value
        
def get_move_result_register(insn):
    if "move_result" not in insn.getMnemonicString():
        raise Exception("Not a move_result: {} @ {}".format(insn, insn.getAddress()))
        
    return get_register_or_pair(insn.getResultObjects()[0])

def is_double_width_param(param_type):
    return param_type in ["J", "D"]
        
def get_num_regs_from_param_types(param_type_list):
    """ calculate how many registers we need for a given set of param types - specifically, handle the double width param types """
    count = 0
    for param_type in param_type_list:
        if is_double_width_param(param_type): 
            count += 2
        else:
            count += 1
    
    return count
    
class ObjectStateTracker(object):
    """ Record state changes for objects, by their pointers """
    tracker = None
    predecessors = None
    def __init__(self):
        self.tracker = list()
        self.predecessors = list()
        
    def add_predecessor(self, predecessor_tracker):
        self.predecessors.append(predecessor_tracker)
        
    def extend(self, chunk_tracker):
        """ Extend the tracking with the results from the next chunk tracker - used to join state trackers from chunks """
        # update anything in the chunk tracker with this as the tracker
        for object_ref in chunk_tracker.tracker:
            object_ref.set_tracker(self)
        
        # add all the changes to this tracker
        self.tracker.extend(chunk_tracker.tracker)
        
        # sort by address
        self.tracker.sort(key=lambda ref: ref.get_address())
    
    def add_object_change(self, object_ref):
        """ Add a change to the given reference"""
        # tell the object where it's being tracked
        object_ref.set_tracker(self)
        
        self.tracker.append(object_ref)
        
        # sort by address
        self.tracker.sort(key=lambda ref: ref.get_address())
        
    def get_object_changes(self, object_ref):
        """ Return an ordered list of changes for this object """
        output_list = []
        
        # make sure the reference we have is a base reference
        object_base_ref = object_ref.resolve_to_base()
        
        for change_ref in self.tracker:
            change_base_ref = change_ref.resolve_to_base()
            if change_base_ref == object_base_ref: # TODO might need to do smarter matching
                output_list.append(change_ref)
                
        # sort by address
        output_list.sort(key=lambda ref: ref.get_address())
        
        return output_list
            
    def get_last_object_ref(self, object_ref, loop_stack=None):
        """ Return the last reference to the object that we've seen in this tracker (or preds)"""
        
        # TODO deduplicate this with loop
        # check if we're in the stack
        if loop_stack is not None:
            if self in loop_stack:
                # expected, saw ourselves. stop looping and return None. The multivalue containing the loop will catch that and remove from its list of values (assumption: every loop only occurs in the context of a multivalue with values fed to the top of the loop - otherwise, the value would be undefined in the first run of the loop).
                return None
        else:
            # no loop stack, create one
            loop_stack = list()
            
        # okay, didn't find ourself in the loop stack - add ourselves to the list, ask for a resolve, then remove ourself once it comes back
        loop_stack.append(self)
        
        changes = self.get_object_changes(object_ref)
        if len(changes) > 0:
            loop_stack.pop()
            return changes[-1]
        
        # not here, got to go through the preds
        lasts = list()
        
        # got to try the predecessors
        for pred in self.predecessors:
            state = pred.get_last_object_ref(object_ref, loop_stack)
            if state is not None: # state == None means this was a loop
                if isinstance(state, values.MultiValue):
                    lasts.extend(state.assignment_list)
                else:
                    lasts.append(state)
                        
        #expect to be at the top of the stack when it comes back
        if loop_stack[-1] != self:
            print(loop_stack)
            raise Exception("Ooops? Loop stack didn't return with right loop at the top")
            
        loop_stack.pop()
                    
        # remove duplicates
        lasts = list(set(lasts))
        
        last_ref = None
        if len(lasts) > 1:
            last_ref = values.MultiValue(lasts)
        elif len(lasts) == 1:
            last_ref = lasts[0]
            
        return last_ref
         
            
    def get_prev_object_ref_before_addr(self, object_ref, address):
        """ Return the last refernce to the object before the given address
        """
        address = ghidra_utils.enforce_raw_address(address)
        
        changes = self.get_object_changes(object_ref)
        
        # work backwards through the changes
        changes.reverse()
        
        last_ref = None
        for change_ref in changes:
            if change_ref.get_address() < address:
                # this ref is the first one that happens before the address
                last_ref = change_ref
                break
                
        if last_ref is None:
            lasts = list()
        
            # got to try the predecessors
            for pred in self.predecessors:
                # be careful handling loops
                #if isinstance(pred, values.Loop):
                #    raise Exception("need to handle loops (change address won't be less than address...)")
                #else:
                state = pred.get_last_object_ref(object_ref)
                if isinstance(state, values.MultiValue):
                    lasts.extend(state.assignment_list)
                else:
                    lasts.append(state)
                    
            # remove duplicates
            lasts = list(set(lasts))
            if len(lasts) > 1:
                last_ref = values.MultiValue(lasts)
            else:
                last_ref = lasts[0]
                
        return last_ref
        
      
    def get_object_state_at_addr(self, object_ref, address):
        """ Return the state of the referenced object immediately BEFORE the execution of the address 
        """
        
        last_ref = self.get_prev_object_ref_before_addr(object_ref, address)

        last_values = None
        if isinstance(last_ref, values.MultiValue):
            last_values = [ref.resolve_to_object_value() for ref in last_ref.assignment_list] 
        else:
            last_values = [last_ref.resolve_to_object_value()]
          
        # remove duplicates (e.g., if multiple paths return untouched argvalue)
        # TODO implement equality for objectvalues to avoid dupes there?
        last_values = list(set(last_values))
        if len(last_values) > 1:
            last_value = values.MultiValue(last_values)
        else:
            last_value = last_values[0]
                
        # TODO if is arg value and reaches start - return untouched argvalue?
        
        return last_value
        
class ChunkTrace(object):
    start_addr = None 
    end_addr = None
    inputs = None   # dictionary of registers used in this chunk, mapped to the values for predecessors when linked together
    outputs = None  # dictionary of registers at the end of this chunk
    line_state = None # dictionary of input state for each line in the chunk
    lines = None
    call = None # set to the call object if there's one in this chunk (so you can easily call resolve on it)
    object_state = None
    parent_block_trace = None
    return_address = None # if there's a return in the chunk, here's where. propagate up into block/function traces to allow easy gathering of outputs
    static_fields = None # if a static field is referenced for anything, record it here (set of field strings). propagate up into block/function traces to make it easy to see where static fields could be used as "outputs"
    
    def has_addr(self, addr):
        addr = ghidra_utils.enforce_raw_address(addr)
    
        return (self.start_addr <= addr) and (addr < self.end_addr) # note - end is the start of the first line in next chunk
    
    def get_last_assignment(self, reg):
        """ return the last assignment in the current state, or an out of code chunk. """
        if isinstance(reg, ghidra.program.model.lang.Register):
            reg = str(reg.getName())
        
        if reg not in self.outputs:
            # see if it's in the input list already
            if reg not in self.inputs: # add it!
                self.inputs[reg] = values.OutOfChunkValue(reg, self.start_addr)
            value = self.inputs[reg]
        else:
            value = self.outputs[reg]
            
        return value
    
    def __init__(self, start_addr, end_addr, program=None, parent_block_trace=None): 
        """ start = start of first line in the chunk. end = start of first line in next chunk """
        self.start_addr = start_addr
        self.end_addr = end_addr
        self.parent_block_trace = parent_block_trace
        
        self.insn_inputs = dict()
        self.inputs = dict()
        self.outputs = dict() # we'll use this to track the state as we move through the chunk
        self.object_state = ObjectStateTracker()
        self.static_fields = set()
        
        dex_header = dextypes.dex_header(program=program)
        
        #print("Chunk {} {}".format(start_addr, end_addr))
        
        self.insns = []
        address = ghidra_utils.get_address(self.start_addr, program=program)
        while address.getOffset() < self.end_addr:
            insn = ghidra_utils.get_instruction_at_address(address, program=program)
            self.insns.append(insn)
            next = insn.getNext()
            if next is None:
                break
            address = next.getAddress()
            
        try:
            for insn in self.insns:   
                #print("{}:{}".format(insn.getAddress(), insn))
                operands = [insn.getOpObjects(i)[0] for i in range(0, insn.getNumOperands())]

                input_regs = set()
                for input in insn.getInputObjects():
                    if isinstance(input,ghidra.program.model.lang.Register) and input.getName() != "resultregw":
                        input_regs.add(get_register_or_pair(input)[0])
                        # TODO register pairs are only as first register here
                
                # note: register pairs only show up as the first register here?
                # also note: for invoke/range instructions, this will include a spurious register at the end
                
                # take a copy of the outputs before this line operates on them, so we can record the line inputs later
                prev_outputs = self.outputs.copy()
                
                mnem = insn.getMnemonicString()
                value = None

                if "new_" in mnem:
                    # one of new-instance, or 3 different new-arrays - all have type as the last operand               
                    
                    if mnem == "new_instance":
                        # it's an object!
                        # new object, so create a reference for it
                        obj_value = values.ObjectInit(create_addr=insn.getAddress(), program=insn.getProgram(), type=dex_header.get_type(operands[-1].getValue()))
                        value = values.ObjectReferenceInit(insn.getAddress(), insn.getProgram(), obj_value)
                        self.object_state.add_object_change(value)
                    else:            
                        # know the type info, but the value is none because this is just an empty block so far
                        value = values.ArrayValue(dex_header.get_type(operands[-1].getValue()))
                    
                    if "filled_" in mnem:
                        # note we leave the touches regs unchanged
                        dest = get_move_result_register(insn.getNext())
                    else:
                        dest = str(insn.getResultObjects()[0].getName())
                        input_regs = input_regs - set([dest])
                    
                    self.outputs[dest] = value             
                elif "const" in mnem:
                    # first register is always the destination
                    dest = get_register_or_pair(insn.getResultObjects()[0])
                    input_regs = input_regs - set(dest)

                    # despite the first 4 being objects, we don't use ObjectReference for them, because they can't be modified
                    if "string" in mnem:
                        obj_value = values.ConstantValue(dex_header.get_string(operands[-1].getValue()), "Ljava/lang/String;")
                        value = values.ObjectReferenceInit(insn.getAddress(), insn.getProgram(), obj_value)
                        self.object_state.add_object_change(value)
                    elif "const_method_handle" == mnem:
                        # todo - implement getting method from dextypes - type could be type of method?
                        obj_value = values.ConstantValue(operands[-1].getValue(), "Ljava/lang/Method;")
                        value = values.ObjectReferenceInit(insn.getAddress(), insn.getProgram(), obj_value)
                        self.object_state.add_object_change(value)
                    elif "const_method_type" == mnem:
                        # todo - implement getting proto from dextypes - type could be the proto details?
                        obj_value = values.ConstantValue(operands[-1].getValue(), "proto")
                        value = values.ObjectReferenceInit(insn.getAddress(), insn.getProgram(),obj_value)
                        self.object_state.add_object_change(value)
                    elif "const_class" == mnem:
                        obj_value = values.ConstantValue(dex_header.get_type(operands[-1].getValue()), "Ljava/lang/Class;")  # type could be tpye of class
                        # ??? - or could be type of method?
                        value = values.ObjectReferenceInit(insn.getAddress(), insn.getProgram(),obj_value)
                        self.object_state.add_object_change(value)
                    else:
                        # integers!
                        # todo - difft sizes? floats/etc
                        value = values.ConstantValue(operands[-1].getValue(), "number")
                        
                    set_register_or_pair(self.outputs, dest, value)
                        
                elif "invoke" in mnem:
                    # assignment to result register, all the regs here are touches. if they're objects, create new object values with this call and set them here (in case they're modified by the call)
                    method = dex_header.get_method(operands[0].getValue())
                    param_types = method.method_prototype.parameters
                    this = None
                    param_list = list()
                    
                    if "range" in mnem:
                        # the first operand is the method, the second arg is the number of registers, the third operand is the first arg register 
                        reg_idx = int(operands[2].getName()[1:])
                        
                        # note: input_regs is garbage on ranges, so rebuild it from scratch as we identify the regs
                        input_regs = set()
                        
                        if "static" not in mnem:                        
                            # grab the first reg as this
                            reg = "v"+str(reg_idx)
                            input_regs.add(reg)
                            this = ParamValue(reg, self.get_last_assignment(reg))
                            reg_idx += 1
                        
                        for param_type in param_types:
                            reg = "v"+str(reg_idx)
                            input_regs.add(reg)
                            param_list.append(ParamValue(reg, self.get_last_assignment(reg)))
                            
                            if is_double_width_param(param_type):
                                reg_idx += 2
                            else:
                                reg_idx += 1
                        
                    else:
                        operand_idx = 1  # Skip the magic operand that points to method defs
                        param_idx = 0
                        while operand_idx < len(operands):
                            operand = operands[operand_idx]
                            
                            reg = str(operand.getName())
                            # grab the first reg as this
                            if "static" not in mnem and this is None:
                                this = ParamValue(reg, self.get_last_assignment(reg))    
                            else:
                                # params!
                                param_list.append(ParamValue(reg, self.get_last_assignment(reg)))
                                # if it's a double width param, remember to skip the next operand
                                if is_double_width_param(param_types[param_idx]):
                                    operand_idx += 1
                                    # remove the second reg from the input regs
                                    input_regs = input_regs - set([str(operands[operand_idx].getName())])
                                param_idx += 1
                            
                            operand_idx += 1

                    call = Call(insn, method, this, param_list)
                    
                    if "static" not in mnem:
                        if call.is_target_modified():
                            # make sure we add the object arg first
                            obj_value = values.ObjectModifiedByCall(call=call, params_idx=-1, args_reg=this.reg)
                            # record the reference to this object using the value in the param
                            value = values.ObjectReference(insn.getAddress(),insn.getProgram(), this.value, obj_value)
                            self.object_state.add_object_change(value)
                            
                            # work out which register
                            dest = this.reg
                            self.outputs[dest] = value
                            
                    for idx, param_type in enumerate(param_types):
                        if param_type.startswith("["): # it's an array!
                            # TODO implement handling
                            pass
                        elif param_type.startswith("L"): # it's an object
                            if call.is_param_modified(idx):
                                # treat each object used in the call as a new object value set into that reg
                                obj_value = values.ObjectModifiedByCall(call=call, params_idx=idx, args_reg=param_list[idx].reg)
                                
                                # record the reference to this object using the value in the param
                                value = values.ObjectReference(insn.getAddress(), insn.getProgram(), param_list[idx].value, obj_value)
                                
                                # update the object state
                                self.object_state.add_object_change(value)
                                
                                # work out which register
                                dest = param_list[idx].reg
                                self.outputs[dest] = value
                            
                    if not method.method_prototype.return_type == "V": # if it has a void return type, doesn't return a result
                        reg_or_pair = None
                        try:
                            # get the next line for the move-result op
                            reg_or_pair = get_move_result_register(insn.getNext())
                        except Exception:
                            # didn't find a move result - result is ignored, so don't bother with this
                            pass
                        
                        if reg_or_pair is not None:
                        
                            # this handles the possibility of double width returns
                            result = values.ResultValue(insn.getAddress(), insn.getProgram(), method.method_prototype.return_type, call)
                            
                            if method.method_prototype.return_type.startswith("L"):
                                reference = values.ObjectReferenceResult(insn.getAddress(), insn.getProgram(), result)
                                
                                # set the object state
                                self.object_state.add_object_change(reference)
                                # set the result reg to the object reference
                                result = reference
                            
                            set_register_or_pair(self.outputs, reg_or_pair, result)
                            
                    self.call = call        

                    # TODO check the arguments for the method, use as hints in working out if our types are right
                elif "move_result" in mnem:
                    # no-op - we've already grabbed this line (must always be next instruction after an invoke or other use)
                    continue
                elif "move_exception" in mnem:
                    # not sure how to handle exceptions yet
                    continue
                elif "move" in mnem:
                    dest = get_register_or_pair(insn.getResultObjects()[0])
                    input_regs = input_regs - set(dest)
                    src = get_register_or_pair(operands[1])[0]
                    
                    value = self.get_last_assignment(src)
                    
                    set_register_or_pair(self.outputs, dest, value)

                elif 'check_cast' in mnem:
                    # A check cast is effectively a reassignment to the same register
                    # but updating the type. We retain type information from previous
                    # assignments, so we don't lose information.
                    pass
                    
                    # TODO implement
                    """ass = Assignment(line)
                    dest = get_register_or_pair(insn.getResultObjects()[0])
                    src = dest
                    input_regs = input_regs - set([dest])
                    ass.reg = dest
                    ass.value = get_last_assignment(writes, src, sark_code_block)
                    ass.value.type = dex_header.get_type(operands[-1].getValue())"""

                elif "put" in mnem:
                    # TODO could check types
                    src = self.get_last_assignment(get_register_or_pair(operands[0])[0])
                    if "aput" in mnem:
                        array = self.get_last_assignment(operands[1])
                        idx = self.get_last_assignment(operands[2])
                    else:
                        field = dextypes.dex_field(dex_header, operands[-1].getValue())
                        if "iput" in mnem:
                            obj_ref = self.get_last_assignment(operands[1])
                            
                            # note the reference to the object
                            new_object = values.ObjectModifiedField(insn.getAddress(), insn.getProgram(), field=field, value=src)
                            
                            value = values.ObjectReference(insn.getAddress(), insn.getProgram(), obj_ref, new_object)
                            
                            # update the object state
                            self.object_state.add_object_change(value)
                            
                            # update the object register - set the new object back into the original object's reg
                            self.outputs[operands[1]] = value
                            
                        else: # sput/static
                            # record the static field as a "register" to output to
                            self.outputs[str(field)] = src
                            # record the static field
                            self.static_fields.add(str(field))
                    
                elif "get" in mnem:
                    dest = get_register_or_pair(insn.getResultObjects()[0])
                    
                    input_regs = input_regs - set(dest)

                    if "aget" in mnem:
                        if mnem.endswith("object"):
                            # type from array - TODO work it backwards
                            type = "OBJECT"
                        elif mnem.endswith("boolean"):
                            type = "bool"
                        elif mnem.endswith("char"):
                            type = "char"
                        else:
                            type = "number"

                        value = values.DataValue(insn.getAddress())

                    else:
                        # type from field reference
                        field = dextypes.dex_field(dex_header, operands[-1].getValue())
                        if "iget" in mnem:
                            # instance field, object is important
                            object = self.get_last_assignment(operands[1])
                            value = values.InstanceFieldValue(insn.getAddress(), insn.getProgram(), field, object)
                            
                            if field.type.startswith("L"):
                                # the field is an object, so we need to use a reference pointer
                                value = values.ObjectReferenceInstanceField(insn.getAddress(), insn.getProgram(),value, field)
                                self.object_state.add_object_change(value)
                        else: # sget
                            # static field                       
                            value = values.StaticFieldValue(insn.getAddress(), insn.getProgram(), field)
                            
                            if field.type.startswith("L"):
                                # the field is an object, so we need to use a reference pointer
                                value = values.ObjectReferenceStaticField(insn.getAddress(),insn.getProgram(), value, field)
                                self.object_state.add_object_change(value)
                                
                                # we care about getting static fields that are objects, because we can modify them and leak stuff out of the function that way
                                # record the static field
                                self.static_fields.add(str(field))
                        
                    set_register_or_pair(self.outputs, dest, value)
                elif any(mnem.startswith(op) for op in ['cmp']):
                    dest = get_register_or_pair(insn.getResultObjects()[0])
                    input_regs = input_regs - set(dest)
                    left = get_register_or_pair(operands[1])[0]
                    right = get_register_or_pair(operands[2])[0]
                    
                    value = values.CmpValue(insn.getAddress(), insn.getProgram(), left=self.get_last_assignment(left), right=self.get_last_assignment(right))
                    
                    self.outputs[dest[0]] = value
                elif any(mnem.startswith(op) for op in ['if', 'sparse_switch']):
                    # ifs/switches are only for touches atm. Path following for the future
                    pass
                elif mnem.startswith("return"):
                    # discard the input regs - they've got junk like "sp" in them
                    input_regs = []
                    self.return_address = insn.getAddress()
                    if mnem != "return_void": 
                        src = get_register_or_pair(operands[0])[0]
                        self.outputs[RETURN_REG] = values.ReturnValue(insn.getAddress(), insn.getProgram, self.get_last_assignment(src))
                        
                elif mnem.startswith("goto"):
                    # no registers
                    input_regs = []
                elif mnem == "array_length" or mnem == "instance_of":
                    dest = get_register_or_pair(insn.getResultObjects()[0])[0]
                    input_regs = input_regs - set([dest])
                    # TODO maybe we could link to the relevant register for easier resolving?
                    value = values.ResultValue(insn.getAddress(), insn.getProgram(),  "number")
                    self.outputs[dest] = value
                elif any(mnem.startswith(op) for op in ["add", "mul", "sub", "rsub", "rem", "div", "and", "or", "xor", "shl", "shr", "ushr"]):
                    dest = get_register_or_pair(insn.getResultObjects()[0])
                    
                    if "_lit" in mnem or "rsub" in mnem: # AAARGH. Dalvik bytecode deliberately doesn't have the _lit16 suffix for rsub, because it's "the main opcode of its family".
                        src = get_register_or_pair(operands[1])[0] # src only needs to care about first reg
                        partial_val = self.get_last_assignment(src)
                        lit_val = values.ConstantValue(operands[2].value, "number")
                        value = values.CombinedValue(mnem, [partial_val, lit_val])
                        input_regs = input_regs - set(dest)
                    elif "2addr" in mnem:
                        ### TODO FIXME - for vw2, get_last_assignment(dest[0]) creates Ooc for v2, but not for v3
                        value = values.CombinedValue(mnem, [self.get_last_assignment(dest[0]), self.get_last_assignment(get_register_or_pair(operands[1])[0])])
                        # note: stores back into itself, so don't remove from touched regs
                    else:
                        value = values.CombinedValue(mnem, [self.get_last_assignment(get_register_or_pair(operands[1])[0]), self.get_last_assignment(get_register_or_pair(operands[2])[0])])
                        input_regs = input_regs - set(dest)
                        
                    set_register_or_pair(self.outputs, dest, value)

                elif any(mnem.startswith(op) for op in ["neg", "not", "int_to", "long_to", "float_to", "double_to"]):
                    dest = get_register_or_pair(insn.getResultObjects()[0])
                    input_regs = input_regs - set(dest)
                    src = get_register_or_pair(operands[1])[0] # src only needs to care about first reg
                    value = values.CombinedValue(mnem, [self.get_last_assignment(src)])
                    set_register_or_pair(self.outputs, dest, value)
                elif "switch" in mnem:
                    # just touches, not modifications
                    pass
                elif "throw" in mnem:
                    # could be handy to handle exceptions
                    pass
                elif "monitor" in mnem:
                    # get/release lock for synchronized statements - not interesting to us now
                    pass         
                elif "fill_array_data" in mnem:
                    # load an array with the specified data. TODO implement when we need to work with arrays
                    # just remove the references
                    dest = get_register_or_pair(operands[0]) # note: not in resultobjects
                    input_regs = input_regs - set(dest)
                else:
                    raise Exception("Unknown insn: " + str(insn))
                    
                # record every reg we need in the inputs
                self.insn_inputs[insn.getAddress().getOffset()] = dict()
                for reg in input_regs:
                    if reg not in self.inputs and reg not in self.outputs:
                        self.inputs[reg] = values.OutOfChunkValue(reg, start_addr)
                    
                    if reg in prev_outputs:
                        self.insn_inputs[insn.getAddress().getOffset()][reg] = prev_outputs[reg]
                    else:
                        self.insn_inputs[insn.getAddress().getOffset()][reg] = self.inputs[reg]

        except Exception as e:
            print("Failed parsing insn {} @ {}".format(insn, insn.getAddress()))
            raise

    def __str__(self):
        output = "ChunkTrace("
        for insn in self.insns:
            output += "\n\t{}: {}".format(insn.getAddress(), insn)
        output += "\n)"
    
        return output

    def __repr__(self):
        return self.__str__()    
        
    def print_chunk(self):
        print("\tChunk: 0x{:x}".format(self.start_addr))
        print("\t\tInputs:")
        for register, val in self.inputs.items():
            print("\t\t\t{}\t{}".format(register, val))
            
        for insn in self.insns:
            print("\t\t\t{}: {}".format(insn.getAddress(), insn))
            
        print("\t\tOutputs:")
        for register, val in self.outputs.items():
            print("\t\t\t{}\t{}".format(register, val))
            
    
        
class BlockTrace(object):
    block = None
    inputs = None   # dictionary of registers used in this block, mapped to the values for predecessors when linked togethre
    outputs = None  # dictionary of registers at the end of this block
    chunks = None   # dictionary of chunks by start address
    calls = None    # dictionary of call chunks by address
    object_state = None # tracks object state within the blocks
    return_address = None
    static_fields = None
    
    def __init__(self, block):
        self.block = block
        self.chunks = dict()
        self.calls = dict()
        self.static_fields = set()
        
        
        #print("Block {} ".format(block.getFirstStartAddress()))
    
        # find the calls to split this up into chunks
        start_addr = get_block_address(block)
        end_addr = start_addr
        insn = ghidra_utils.get_instruction_at_address(block.getFirstStartAddress(), program=block.getModel().getProgram())
        #print(block)
        while insn is not None and block.contains(insn.getAddress()):
            #print("{}: {}".format(insn.getAddress(), insn))
            mnem = insn.getMnemonicString()
            if "invoke" in mnem:
                # it's a call! stop the current chunk (if there is one), save it, and create a chunk for the call
                if start_addr != end_addr:
                    self.chunks[start_addr] = ChunkTrace(start_addr, end_addr, program=block.getModel().getProgram(), parent_block_trace=self)
                            
                start_addr = insn.getAddress().getOffset()
                # check if there's a move_result next
                next_insn = insn.getNext()
                if next_insn is not None and "move_result" in next_insn.getMnemonicString():
                    # yup! include it in the chunk - end address will be the start of the line after the move result
                    next_next_insn = next_insn.getNext()
                    if next_next_insn is not None:
                        end_addr = next_next_insn.getAddress().getOffset()
                    else:
                        end_addr = next_insn.getAddress().getOffset() + next_insn.getLength()
                else:
                    # nope! end address will be the start of this next line
                    end_addr = next_insn.getAddress().getOffset()
                    
                # save the call chunk
                self.chunks[start_addr] = ChunkTrace(start_addr, end_addr, program=block.getModel().getProgram(), parent_block_trace=self)
                self.calls[start_addr] = self.chunks[start_addr]
                
                # start a new chunk
                start_addr = end_addr
            elif "move_result" in mnem:
                # do nothing, covered by invoke - just throw in a check to make sure we're not picking this up in some other case
                assert (start_addr == end_addr), "Got an unexpected move_result in the middle of a chunk"
            elif "return" in mnem:
                # record the return!
                next_insn = insn.getNext()
                if next_insn is not None:
                    end_addr = next_insn.getAddress().getOffset()
                else:
                    end_addr = insn.getAddress().getOffset() + insn.getLength()
            else:
                # ordinary instruction - just update end_addr to include it in the current chunk
                next_insn = insn.getNext()
                if next_insn is not None:
                    end_addr = next_insn.getAddress().getOffset()
                else:
                    end_addr = insn.getAddress().getOffset() + insn.getLength()
                
            insn = ghidra_utils.get_instruction_at_address(end_addr, program=block.getModel().getProgram())
                
        # save the last chunk, if there is one
        if start_addr != end_addr:
            self.chunks[start_addr] = ChunkTrace(start_addr, end_addr, program=block.getModel().getProgram(), parent_block_trace=self)
            
        self.inputs = dict()
        self.outputs = dict()
        self.object_state = ObjectStateTracker()
            
        # now, work through all the chunks in order, recording inputs and building up outputs
        for chunk_addr in sorted(self.chunks.keys()):
            chunk = self.chunks[chunk_addr]
            # add any inputs that we don't already have in the outputs (from previous chunks) or inputs (outofcodeblock values) to the inputs
            for input_reg, input_val in chunk.inputs.items():
                if input_reg not in self.outputs:
                    if input_reg not in self.inputs:
                        self.inputs[input_reg] = values.OutOfCodeBlockValue(input_reg, self.block)
                    
                    # update the outofchunk value with the outofcodeblock value
                    input_val.value = self.inputs[input_reg]
                else:
                    # update the outofchunk value with the value we've built up
                    input_val.value = self.outputs[input_reg]
                        
            # update the outputs as our internal state
            for output_reg, output_val in chunk.outputs.items():
                self.outputs[output_reg] = output_val
                
            # add the object state changes to our object state
            self.object_state.extend(chunk.object_state)
            
            # if there's a return in the chunk, set it in the block (should only be one/block, they're basic blocks)
            if chunk.return_address is not None:
                self.return_address = chunk.return_address
            
            # pull up any static field references from the chunk
            for static_field in chunk.static_fields:
                self.static_fields.add(static_field)
            
    def __str__(self):
        return "BlockTrace({})".format(self.block)

    def __repr__(self):
        return self.__str__()   

    def print_block(self):
        print("Block: 0x{:x}".format(self.block.getFirstStartAddress().getOffset()))
        print("Inputs:")
        for register, val in self.inputs.items():
            print("\t{}\t{}".format(register, val))
        if len(self.calls.keys()) > 0:
            print("Calls:")
            for call_chunk in [self.calls[chunk_addr] for chunk_addr in sorted(self.calls.keys())]:
                call_chunk.print_chunk()
            
        print("Outputs:")
        for register, val in self.outputs.items():
            print("\t{}\t{}".format(register, val))
            
    def find_chunk_for_addr(self, addr):
        for chunk in [self.chunks[chunk_addr] for chunk_addr in sorted(self.chunks.keys())]:
            if chunk.has_addr(addr):
                return chunk
                
        raise Exception("Didn't find chunk for {} in {}".format(addr, self))
            
            
    def find_regs_at_address(self, address):
        """ Find the value of all registers involved in given address - NOTE: This contains the values of the registers BEFORE the instruction is invoked. """ 

        try:
            chunk = self.find_chunk_for_addr(address)
            regs = chunk.insn_inputs[ghidra_utils.enforce_raw_address(address)]
        except Exception as e :
            print(address)
            self.print_block()
            raise
        return regs
        
    def find_call_at_address(self, address):
        """ Find the call at the given line, ready to inspect the args or resolve it. returns none if no call there"""
        return self.find_chunk_for_addr(address).call
        
    def find_object_state_at_address(self, object_reference, address):
        """ Find the state of an object at the given address - NOTE: This will be the state BEFORE the instruction is invoked """ 
        return self.object_state.get_object_state_at_addr(object_reference, address)

class FunctionTrace(object):
    """ Record the assignments, touches, and params at use in a function """
    function = None
    block_traces_dict = None # map block addrs to the block traces
    params_dict = None        # map of param names to symbolic values at the start of the function
    cycles = None # set of loop tuples, with first element as top of loop (head), and second element as block that loops back to it (tail)
    return_address = None
    static_fields = None
    
    def __init__(self, function, do_link=True):
        self.function = function
        self.block_traces_dict = dict()
        self.params_dict = dict()
        self.params_list = list()
        self.params_object_state = ObjectStateTracker() # initial object state for the arg values
        self.return_addresses = list()
        self.static_fields = set()
        
        program = self.function.getProgram()
        
        self.cycles = set(find_loops(function.getEntryPoint(), program))
        self.__traced_blocks = list()
        

        def walk_down_blocks(trace, block):
            block_addr = get_block_address(block)
            if block_addr not in trace.block_traces_dict:
                trace.block_traces_dict[block_addr] = BlockTrace(block)

                for next_block in get_destinations(block, getMonitor()):
                    walk_down_blocks(trace, next_block)

        # collect the traces from each of the code blocks in the function
        entry_block = ghidra_utils.get_basic_block_at_address(address=self.function.getEntryPoint().getOffset(), program=program)
        walk_down_blocks(self, entry_block)
        
        dex_header = dextypes.dex_header(program=program)
        
        # boo, can only get the method id offset from the comment
        method_id_offset = ghidra_utils.get_address(self.function.getComment().split("Method ID Offset: ")[1].strip(), program=program)
        method_id = method_id_offset.subtract(dex_header.methods)/dextypes.SIZE_OF_METHOD_ELEMENTS
        
        method = dex_header.get_method(method_id)

        param_types = method.method_prototype.parameters

        # get number of registers/size of input args for the method (come before the function - regs, then ins, then outs - grab from the hdr size to the outs offset)
        num_regs = int(self.function.getComment().split("Method Register Size: ")[1].split("\n")[0])
        size_input = int(self.function.getComment().split("Method Incoming Size: ")[1].split("\n")[0])
        
        # argument registers are the last (size_input) regs
        reg_idx = num_regs - size_input
                                        
        if size_input > get_num_regs_from_param_types(param_types):  # implicit this param, so it's an instance method
            reg = "v" + str(reg_idx)
            
            value = values.ArgValue("this", function=self.function, type=method.clazz) # note: the type might not be exactly what was passed in, with inheritance/etc
            
            reference = values.ObjectReferenceArg(0, self.function.getProgram(), value ) # fake out the address of the change, so we'll always pick it, even if we're looking at the start of the function
            
            self.params_object_state.add_object_change(reference) 
            
            # store the param both by reg and by param id
            self.params_dict[reg] = reference 
            self.params_dict["this"] = reference 
            reg_idx += 1 # always one, object reference, can't be a double/etc
            
        param_idx = 0
        for type in param_types:
            reg = "v" + str(reg_idx)
            param = "p"+str(param_idx)
            value = values.ArgValue(param, function=self.function, type=type) #TODO iv instead of p?
            if type.startswith("L"): # it's an object type, so we need to wrap the argvalue with a reference
                reference = values.ObjectReferenceArg(0, self.function.getProgram(), value)  # fake out the address of the change, so we'll always pick it, even if we're looking at the start of the function
                self.params_object_state.add_object_change(reference)
                value = reference
            self.params_dict[reg] = value
            self.params_list.append(value)
            
            if is_double_width_param(type):
                reg_idx += 1
                param_idx += 1
                reg = "v" + str(reg_idx)
                self.params_dict[reg] = values.WideValue(param) # this is the second part of a wide argument (not stored by param idx)

            reg_idx += 1
            param_idx += 1

        if do_link:          
            self.link()   

    
    def link(self):   
        """ Some loop assumptions:
        * Only valid for/while loop constructs have to be considered - e.g., you can't enter a loop from multiple points. (can exit from multiple points, though - e.g., break? does that affect anything?
        * This implies that walking back through the predecessesors will always encounter the head before reaching a non-loop node 
            * Therefore, once we've followed a loop, we're in a loop until we reach the head again - and because this function doesn't recheck already visited nodes, we don't need to worry about handling that 
        * Loops can be nested (while(x){while(y){}}), but otherwise don't overlap
        """    
        # TODO what about establishing paths instead?
        for block_addr, block_trace in self.block_traces_dict.items():
            
            # if there's a return in the block, record it for the function
            if block_trace.return_address is not None:
                self.return_addresses.append(block_trace.return_address)
            
            # pull up any static field references from the block
            for static_field in block_trace.static_fields:
                self.static_fields.add(static_field)
                        
            predecessors = { get_block_address(pred_block): pred_block for pred_block in get_sources(block_trace.block)}
            
            # link up the object states
            if block_addr == ghidra_utils.enforce_raw_address(self.function.getEntryPoint()):
                # initial block - use the initial params object state
                block_trace.object_state.add_predecessor(self.params_object_state)
            
            for pred_addr in predecessors.keys():
                if pred_addr not in self.block_traces_dict:
                    # TODO exception handling, see below. Also duplicate code
                    continue
                pred_trace = self.block_traces_dict[pred_addr]
                        
                pred = pred_trace.object_state
                # mark it as a loop value if it is in a loop, so we can be careful resolving the object
                #if self.is_loop(block_addr, pred_addr):
                #    pred = values.Loop(head_addr=block_addr, tail_addr=pred_addr, value=pred)
                block_trace.object_state.add_predecessor(pred)

            for reg in block_trace.inputs:
            
                assignments = list()
        
                checked_list = [block_addr] # record the original block, so we don't loop back into it - we shouldn't look in it anyway # TODO - what if immediate loop?
                    
                to_check_list = [(pred, block_addr if self.is_loop(block_addr, pred) else None) for pred in predecessors.keys()]
        
                while (len(to_check_list) > 0):
                    pred_addr, loop_head = to_check_list.pop()

                    if pred_addr in checked_list:
                        # we've already looked at this block, so any result is already there
                        continue

                    # record this block so we don't revisit
                    checked_list.append(pred_addr)
                    
                    if pred_addr not in self.block_traces_dict:
                        # probably a move exception (or a block that leads to a move exception - outside the normal control flow)
                        # ignore for now. TODO - might want to implement exception handling. 
                        continue
                        """
                        line = sark.Line(pred_addr)
                        insn = line.insn
                        if 'move_exception' in insn.mnem:
                            raise Exception("Not implemented - handling exceptions")
                            reg = operands[0].reg
                            value = SymbolicValue()
                        else:
                            # Looks like we actually have a bug
                            raise Exception("Couldn't find predicate block trace for {}, and not an exception".format(hex(pred_addr)[:-1]))
                        """
                        
                    pred_trace = self.block_traces_dict[pred_addr]
                    
                    if reg in pred_trace.outputs:
                        # sweet, there was an assignment, record it
                        if loop_head is not None:
                            #print("Creating loop. {}<-{}, {} - from {}".format(hex(loop_head)[:-1], hex(pred_addr)[:-1], reg, hex(block_addr)[:-1]))
                            assignments.append(values.Loop(head_addr=loop_head, tail_addr=pred_addr, value= pred_trace.outputs[reg]))
                        else:
                            assignments.append(pred_trace.outputs[reg])
                    else:
                        # nope. add the predecessors for this block into the to_check_list, if they aren't already there
                        next_blocks = get_sources(self.block_traces_dict[pred_addr].block)
                        next_addrs = [get_block_address(block) for block in next_blocks]
                        for next in next_addrs:
                            if next not in checked_list:
                                next_loop_head = loop_head # keep our loop state if we're in a loop (it's none, otherwise) - this means that we'll correctly identify loops across multiple code-blocks 
                                # need to decide if this next represents a new loop (e.g., could be first loop in linear, or could be loop within a loop)
                                if self.is_loop(pred_addr, next):
                                    next_loop_head = pred_addr # loop starts here!
                                
                                to_check_list.append((next, next_loop_head))
                
                try:
                    if len(assignments) == 0:
                        # it's an argument from the function call - use the trace params
                        block_trace.inputs[reg].value = self.params_dict[reg]
                    elif len(assignments) == 1:
                        block_trace.inputs[reg].value = assignments[0]
                    else:
                        block_trace.inputs[reg].value = values.MultiValue(assignments)
                except Exception as e:
                    print("Looking for {}({}) in {} from {}".format(reg, type(reg), self.params_dict, block_trace.block.getFirstStartAddress()))
                    raise
             
    def get_block_trace_at_address(self, address): # TODO just record the program in the function trace and don't ask for this to be passed in
       return self.block_traces_dict[ghidra_utils.get_basic_block_at_address(address=address,program=self.function.getProgram()).getFirstStartAddress().getOffset()]
             
    def find_regs_at_address(self, address):
        """ Find the value of all registers involved in given insn - NOTE: This contains the values of the registers BEFORE the instruction is invoked. """
        # pick the block that contains the address, and ask it
        block_trace = self.get_block_trace_at_address(address)
        return block_trace.find_regs_at_address(address)
        
    def find_call_at_address(self, address):
        """ Find the call at the given insn, ready to inspect the args or resolve it. returns none if no call there"""
        # pick the block that contains the line, and ask it
        block_trace = self.get_block_trace_at_address(address)
        return block_trace.find_call_at_address(address)
        
    def find_object_state_at_address(self, object_reference, address):
        """ Find the state of an object at the given address - NOTE: This will be the state BEFORE the instruction is invoked """ 
        # pick the block that contains the line, and ask it
        block_trace = self.get_block_trace_at_address(address) 
        return block_trace.find_object_state_at_address(object_reference, address)
                
    def print_blocks(self):
        for block_trace in [self.block_traces_dict[block_addr] for block_addr in sorted(self.block_traces_dict.keys())]:
            block_trace.print_block()
            
    def is_loop(self, block_addr, pred_block_addr):
        """ return true if the edge from block to pred_block represents a loop (e.g., block is the head of a loop and pred is the tail) """
        # OBSERVATIONS: can't rely on backwards edge being a loop (blocks that multiple ifs point to, exception handlers can get written in such a way that they are backwards edges)
        
        return (block_addr, pred_block_addr) in self.cycles
        
    def get_outputs(self):
        """ return a dictionary of outputs, including return register, static fields that have been modified, and argument values that have been modified """
        # TODO what about primitive static fields (e.g., ints?)
        output_list = list()
        
        for return_address in self.return_addresses:
            output_dict = dict()
        
            block_trace = self.get_block_trace_at_address(return_address)
            
            if RETURN_REG in block_trace.outputs: # won't be present if return-void
                ret_value = block_trace.outputs[RETURN_REG].resolve()
                if isinstance(ret_value, values.MultiValue):
                    new_ret_list = list()
                    for rv in ret_value.assignment_list:
                        if isinstance(rv, values.ObjectReference):
                            rv = rv.resolve_to_object_value()
                        new_ret_list.append(rv)
                    ret_value = values.MultiValue(new_ret_list)
                elif isinstance(ret_value, values.ObjectReference):
                    ret_value = ret_value.resolve_to_object_value()
                
                output_dict[RETURN_REG] = ret_value
                
            for param in set(self.params_dict.values()): # use set because we duplicate names (this and vXXX point to same thing)
                if isinstance(param, values.ObjectReference): # only care about objects
                    value = self.find_object_state_at_address(param, return_address)
                    # check if the object has been modified from the original passed in
                    if not(isinstance(value, values.ObjectReferenceBase) and value.get_object_value() == param.get_object_value()): # else, don't record, not modified
                        # modified! add it 
                        output_dict[param.get_object_value()] = value
                        
            # TODO implement for static fields as well
            
            output_list.append(output_dict)
            
        if len(output_list) > 1:
            return values.MultiValue(output_list)
        else:
            return output_list[0]
            
    def sym_exec(self, call, resolved_this, resolved_params_list): # TODO implement depth
            
        result_dict = dict()
            
        try:
            # update the arguments
            if "this" in self.params_dict:
                # get the arg value from the reference, and set the param in it
                self.params_dict["this"].get_object_value().set_call_value(resolved_this)
            
            for idx, param in enumerate(self.params_list):
                if isinstance(param, values.ObjectReference):
                    param.get_object_value().set_call_value(resolved_params_list[idx])
                else:
                    param.set_call_value(resolved_params_list[idx])
            
            # TODO (later) constrain the paths based on the arguments
            
            # get all the possible outputs
            outputs = self.get_outputs()
            
            if isinstance(outputs, values.MultiValue):
                # TODO gross, cleanup 
                # dump associated by return address multivalue dicts down into dict of multivalues (associated by output reg)
                new_outputs = dict() # dict of lists initially, we'll multivalue them at the end
                for output in outputs.assignment_list:
                    for key,value in output.items():
                        if key not in new_outputs:
                            new_outputs[key] = list()
                        new_outputs[key].append(value)
                        
                new_output_dict = dict()
                for key,value in new_outputs.items():
                    if len(value) > 1:
                        new_output_dict[key] = values.MultiValue(value)
                    else:
                        new_output_dict[key] = value[0]
                
                outputs = new_output_dict
            
            # convert arg values to resolve registers
            for key,value in outputs.items():
                if isinstance(key, values.ArgValue):
                    arg = key.argument
                    if arg == "this":
                        key = resolved_this.reg
                    else:
                        key = resolved_params_list[int(arg[1:])].reg
                        
                result_dict[key] = value                
            
        finally:
            # make sure we clear the arguments
            if "this" in self.params_dict:
                self.params_dict["this"].get_object_value().clear_call_value()
            for param in self.params_list:
                if isinstance(param, values.ObjectReference):
                    param.get_object_value().clear_call_value()
                else:
                    param.clear_call_value()

        return result_dict

def find_regs_at_address(address=None, program=None, trace=None):
    ''' Find the values of registers involved in an instruction

    NOTE: This contains the values of the registers BEFORE the
    instruction is invoked.
    '''
    address = ghidra_utils.get_address(address=address,program=program)
    
    if not trace:
        trace = FunctionTrace(ghidra_utils.get_function_at_address(address=address,program=program))

    return trace.find_regs_at_address(address=address)
    
def find_call_at_address(address=None, program=None, trace=None):
    """ Find the call at the given address, ready to inspect the args or resolve it. returns none if no call there"""
    address = ghidra_utils.get_address(address=address,program=program)
    
    if not trace:
        trace = FunctionTrace(ghidra_utils.get_function_at_address(address=address,program=program))

    return trace.find_call_at_address(address=address)


def build_from_function(function):
    return FunctionTrace(function)


def print_address(address=None, program=None):
    ''' Print the values of each register used at the current address .

    NOTE: This contains the values of the registers BEFORE the current
    instruction is invoked
    '''
    for reg, vals in find_regs_at_address(address=address,program=program).items():
        print("{}:\t{}".format(reg, vals))


def print_block(block=None):
    ''' Prints the values for each register within the current block '''
    if block is None:
        block = ghidra_utils.get_basic_block_at_address()

    trace = BlockTrace(block)
    trace.print_block()


def print_blocks(trace=None):
    ''' Print blocks from FunctionTrace in a nice way '''
    if trace is None:
        trace = FunctionTrace(ghidra_utils.get_function_at_address())
    trace.print_blocks()
