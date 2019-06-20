""" 

Implementations of symbolic values etc used for tracking register contents """

import ghidra_utils

class Value(object):
    """ Base value - only for inheritance"""
    def __repr__(self):
        return self.__str__()
    
class ArrayValue(Value):
    """  an array - needs more implementation to track data in/out """
    value = None
    type = None

    def __init__(self, type):
        self.type = type

    def __str__(self):
        return "ArrayValue({type})".format(type=self.type)

    def resolve(self, loop_stack=None):
        # TODO probably attempt to resolve each of the elements
        
        
        return self
    
class ConstantValue(Value):
    """  an actual, direct constant, with a single type """
    value = None
    type = None

    def __init__(self, value, type):
        self.value = value
        self.type = type

    def __str__(self):
        return "ConstantValue({value}, {type})".format(value=self.value, type=self.type)

    def resolve(self, loop_stack=None):
        """ This is already a concrete value - just give it back """
        if self.type in ["Ljava/lang/String;", "number"]:
            return self.value
        
        
        return self

class AppendValue(Value):
    """ Multiple values have been combined in sequence (e.g., used when modelling stringbuilder.append """
    elements = None
    
    def __init__(self, elements, type=None):
        self.elements = elements
        self.type=type
        
    def __str__(self):
        return "AppendValue({}, {})".format(self.elements, self.type)
        
    def resolve(self, loop_stack=None):
        """ Try to resolve each of the elements, and return an AppendValue containing them"""
        resolve_list = list()
        for element in self.elements:
            res = element.resolve(loop_stack)
            if res is not None: # if this is inside a loop, this might be none when we reach the loop head again
                resolve_list.append(res) 
                
        if len(resolve_list) > 1:        
            return AppendValue(resolve_list)
        else:
            return resolve_list[0]
            
    def get_elements(self):
        return self.elements
        
    def extend(self, new_elements):
        if isinstance(new_elements, AppendValue):
            new_elements = new_elements.get_elements()
        self.elements.extend(new_elements)
    
    def append(self, new_element):
        self.elements.append(new_element)
        
class MultiValue(Value):
    """ There are multiple assignments that could have occured (e.g., at the joining of two or more branches) """
    assignment_list = None

    def __init__(self, assignment_list):
        if len(assignment_list) < 2:
            raise Exception("Why multi? {}".format(assignment_list))
        
    
        self.assignment_list = list(set(assignment_list)) # convert to a set and then back, to remove duplicates
        if len(self.assignment_list) < len(assignment_list):
            raise Exception("Dupes~!")
        
        
        for ass in assignment_list:
            if isinstance(ass, MultiValue) and not isinstance(ass,CombinedValue):
                assignment_list.extend(ass.assignment_list)

    def add(self, value):
        """ Add a value to the possibilities """
        self.assignment_list.append(value)
        self.assignment_list = list(set(self.assignment_list)) # convert to a set and then back, to remove duplicates
                
    def __str__(self):
        return "MultiValue({})".format(self.assignment_list)

        
    def resolve(self, loop_stack=None):
        """ Can't pick between the values yet - just return the resolved values as a multivalue """
        ass_list = list()
        for ass in self.assignment_list:
            res = ass.resolve(loop_stack)
            if res is not None: # if this is inside a loop, this might be none when we reach the loop head again
                ass_list.append(res) 
                
        ass_list = list(set(ass_list))
                
        if len(ass_list) > 1:        
            return MultiValue(ass_list)
        else:
            return ass_list[0]

   
            

class CombinedValue(Value):
    operation = None
    value_list = None

    def __init__(self, operation, value_list):
        self.value_list = value_list
        self.operation = operation

    def __str__(self):
        return "CombinedValue({}: {})".format(self.operation, self.value_list)
        
    def resolve(self, loop_stack=None):
        """ TODO - need to implement ["add", "mul", "sub", "rem", "div", "and", "or", "xor", "shl", "shr", "ushr"]):
        ["neg", "not", "int-to", "long-to", "float-to", "double-to"]): """
        return self
        
class WideValue(Value):
    """ a value that has been split across two registers - this is the second register. Should always be using the first reg for values. Shouldn't show up in resolution"""
    
    reg = None
    
    def __init__(self, reg):
        self.reg = reg

    def __str__(self):
        return "WideValue({})".format(self.reg)
        
    def resolve(self, loop_stack=None):
        raise Exception("Wide showed up in resolve! {}".format(self))
    
class SymbolicValue(Value):
    """ An unknown value with a potentially known type """
    type = None

    def __init__(self, type=None):
        self.type = None

    def __str__(self):
        return "SymbolicValue({type})".format(type=self.type)
        
    def resolve(self, loop_stack=None):
        """ can't resolve a symbolic value further atm """
        return self

class ReturnValue(SymbolicValue):
    """ The value indicates a return instruction, and records the address it happened at and the value returned
    
    Note: distinct from a RESULTValue, which is the result on the OUTSIDE of a call - this
    is the return on the INSIDE of a call
    """
    invoke_addr = None
    addr = None
    program = None

    def __init__(self, invoke_addr, program, value):  
        self.invoke_addr = invoke_addr
        self.program = program
        self.addr = invoke_addr
        self.value = value

    def __str__(self):
        return "ReturnValue({address} in {program}, {value})".format(address=self.invoke_addr, program=self.program.name, value=self.value)

    def resolve(self, loop_stack=None):
        return self.value.resolve(loop_stack)
         
class ResultValue(SymbolicValue):
    """ The value is the result of a method call, and you need to resolve it further inside that method"""
    invoke_addr = None
    addr = None
    type = None
    call = None
    program = None

    def __init__(self, invoke_addr, program, type=None, call=None):  # todo preprocess? type info?
        self.invoke_addr = invoke_addr
        self.addr = invoke_addr
        self.type = type
        self.call = call
        self.program=program

    def __str__(self):
        return "ResultValue({address} in {program}, {type}, {call})".format(address=self.invoke_addr, program=self.program, type=self.type, call=self.call)

    def resolve(self, loop_stack=None):
        if self.call is not None:
        
            resolve = self.call.resolve(loop_stack)
            if isinstance(resolve, dict):
                if "return" in resolve:
                    return resolve["return"]
                
            # otherwise we get here... just return the call?
            return self.call
        else:
            # used for array_length/instance_of insns. Work out how to calculate those TODO
            return self
        
class CmpValue(Value):
    """ The value is the result of a comparison operation"""
    addr = None
    left = None
    right = None
    program = None

    def __init__(self, addr, program, left, right):  
        self.addr = addr
        self.left = left
        self.right = right

    def __str__(self):
        return "CmpValue({address} in {program}, {left}, {right})".format(address=self.addr, program=self.program.name, left=self.left, right=self.right)

    def resolve(self, loop_stack=None):
        # todo - implement comparison
        return self

class ArgValue(SymbolicValue):
    """ The value is a parameter at the start of this function, and you need to resolve it further inside callers"""
    argument = None
    function = None
    type = None
    call_value = None

    def __init__(self, argument, function, type=None):  # todo preprocess? type info
        self.argument = argument
        self.function = function
        self.type = type

    def __str__(self):
        return "ArgValue({param} in {function} ({address} in {program}), {type})".format(param=self.argument,function=self.function, address=self.function.getEntryPoint(), program=self.function.getProgram().getName(), type=self.type)
        
    def resolve(self, loop_stack=None):
        """ if we've got a call value, resolve and return that """
        if self.call_value is not None:
            return self.call_value.resolve(loop_stack)
        
        # otherwise, just stick with this
        return self
        
    def set_call_value(self, value):
        """ store a value this argument was called as """
        self.call_value = value
        
    def clear_call_value(self):
        """ Clear the call value when no longer needed """
        self.call_value = None
              
class ObjectReference(Value):
    """ An object reference, which needs to be dereferenced to identify which object we're  working on
        and allow tracking its state around. But first, we probably need to follow things back
        to the base object reference
    """
    tracker = None
    reference_value  = None
    address = None
    obj_value = None
    program = None
        
    def __init__(self, address, program, reference_value, obj_value): 
        self.address = address # where this reference happened
        self.program = program
        self.reference_value = reference_value # can be things like OutOfCodeChunkValue, or another ObjectReference
        self.obj_value = obj_value # what happened to the object to cause us to update the reference
        
    def set_tracker(self, tracker):
        """ record what tracker is looking after this reference - trackers chain together so we can get back to the base ref """
        self.tracker = tracker
        
    def get_address(self):
        return ghidra_utils.enforce_raw_address(self.address)
        
    def get_object_value(self):
        """ Get the immediate object change at this reference """
        return self.obj_value
        
    def resolve_to_base(self, loop_stack=None):
        """ Get the base object reference. If it's a null object, just return 0 """
        # TODO deduplicate this with loop
        # Note: new assumption - all resolves should only visit their own node once - any other time and there's a loop. Could make loop detection simpler...  
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
        
        # make sure we have the actual prev reference value
        prev_reference_value = self.reference_value.resolve() # TODO need to make sure arg values don't go past the start of the function?
        
        # now ask it what it thinks the base is
        base_reference_value = None
        if isinstance(prev_reference_value, MultiValue):
            bases = list()
            for prev_ref in prev_reference_value.assignment_list:
                if isinstance(prev_ref, ConstantValue):
                    assert prev_ref.resolve() == 0, "Constant reference that wasn't null?"
                    bases.append(ObjectReferenceNull())
                else:
                    base = prev_ref.resolve_to_base(loop_stack)
                    if base is not None: # base is None if we hit a loop, so ignore
                        bases.append(base)
            
            # nuke duplicates - expect most will be the same base ref
            bases = list(set(bases))
            
            if len(bases) > 1:
                raise Exception("Multiple baserefs for {} -> {}".format(self, bases))
                # TODO maybe need a multivalue here?
            
            base_reference_value = bases[0]
            
        else:
            if 0 == prev_reference_value:
                base_reference_value = ObjectReferenceNull()
            else:
                base_reference_value = prev_reference_value.resolve_to_base(loop_stack)
                
        #expect to be at the top of the stack when it comes back
        if loop_stack[-1] != self:
            raise Exception("Ooops? Loop stack didn't return with right loop at the top")
            
        loop_stack.pop()
        
        return base_reference_value
        
    def get_previous_reference(self, base_ref=None):
        """ Get the previous reference to this object. As an optimisation, the base_ref can
            be passed in if it's already been calculated
        """
        if base_ref is None:
            base_ref = self.resolve_to_base()
            
        # get the previous reference(s) before this one
        return self.tracker.get_prev_object_ref_before_addr(base_ref, self.get_address())       
        
    def resolve_to_object_value(self, loop_stack=None):
        """ Get the value of the object when this reference was created 
            Note: this is AFTER the instruction at the address has been calculated
        """
        if loop_stack is not None:
            if self in loop_stack:
                """ note: simple assumption is that we're at top of the stack. But possible to have a case where we're not if we involve multiple variables
                    consider a loop where v3 is affected by v2, and both are modified in the loop. we'll loop over v3, see the v2 involvement, and loop over that before eventually finding the same loop again.
                    
                    TODO would be nice to have loops handle multiple regs at the same time, to simplify
                """
        
                # expected, saw ourselves. stop looping and return None. The multivalue containing the loop will catch that and remove from its list of values (assumption: every loop only occurs in the context of a multivalue with values fed to the top of the loop - otherwise, the value would be undefined in the first run of the loop).
                return None
        else:
            # no loop stack, create one
            loop_stack = list()
            
        # okay, didn't find ourself in the loop stack - add ourselves to the list, ask for a resolve, then remove ourself once it comes back
        loop_stack.append(self)
        
        # get the base reference to this object
        base_ref = self.resolve_to_base()
        # get the previous reference to this object
        prev_ref = self.get_previous_reference(base_ref)
        prev_refs = None
        if isinstance(prev_ref, MultiValue):
            prev_refs = prev_ref.assignment_list
        else:
            prev_refs = [prev_ref]
            
        # resolve the value of the object at that state
        resolves = list()
        for prev_ref in prev_refs:
            prev_object_value = prev_ref.resolve_to_object_value(loop_stack) 
            if prev_object_value is not None: # None if loop
                if isinstance(prev_object_value, MultiValue):
                    for prev in prev_object_value.assignment_list:
                        resolves.append(self.get_object_value().perform(prev))
                else:
                    resolves.append(self.get_object_value().perform(prev_object_value))
                
        obj_value = None
        if len(resolves) > 1:
            obj_value = MultiValue(resolves)
        elif len(resolves) == 1:
            obj_value = resolves[0]
            
        #expect to be at the top of the stack when it comes back
        if loop_stack[-1] != self:
            raise Exception("Ooops? Loop stack didn't return with right loop at the top")
            
        loop_stack.pop()
            
        return obj_value
        
    def resolve(self, loop_stack=None):
        """ Allow for working past all the moves/out of chunks/etc - if we resolve an object ref, we just want that ref """
        return self
        
    def __str__(self):
        return "ObjectReference({address} in {program}, {value})".format(address=self.address, program=self.program.getName(), value=self.reference_value)
        
class ObjectReferenceBase(ObjectReference):
    """ The original reference to an object, which all ObjectReferences that refer to that object
        should resolve back to """

    def resolve_to_base(self, loop_stack=None):
        """ this is a base object reference! we're done resolving """
        return self
        
    def get_previous_reference(self, base_ref=None):
        """ No previous reference to a base """
        # TODO what about linking up argvalues to existing objects?
        return None 
        
    def resolve_to_object_value(self, loop_stack=None):
        """ Base object reference, so the value here is the start - just return it """
        return self.get_object_value() 
        
    def resolve(self, loop_stack=None):
        """ this is a base object reference! we're done resolving """
        return self

class ObjectReferenceNull(ObjectReferenceBase):
    """ An object reference to the Null object """
    def __init__(self):
        super(ObjectReferenceNull, self).__init__(address=0, reference_value=None, obj_value=None)
        
    def __str__(self):
        return "ObjectReferenceNull()"
        
class ObjectReferenceArg(ObjectReferenceBase):
    """ An object reference to an argument passed in to the function """
    def __init__(self, address, program, obj_value):
        super(ObjectReferenceArg, self).__init__(address=address, program=program, reference_value=None, obj_value=obj_value)
        
    def __str__(self):
        return "ObjectReferenceArg({address} in {program}, {obj_value})".format(address=self.address, program=self.program.getName(), obj_value=self.obj_value)
        
    ## TODO equality! may need to record program? address?

class ObjectReferenceInit(ObjectReferenceBase):
    """ An object reference to an object created at a location """
    def __init__(self, address, program, obj_value):
        super(ObjectReferenceInit, self).__init__(address=address, program=program, reference_value=None, obj_value=obj_value)
    
    def __str__(self):
        return "ObjectReferenceInit({address} in {program})".format(address=self.address, program=self.program.getName(),)
        
class ObjectReferenceInstanceField(ObjectReferenceBase):
    """ An object reference to an object pulled out of a field """
    field = None
    # TODO improvement - we should actually tie this to the parent object
    def __init__(self, address, program, obj_value, field):
        super(ObjectReferenceInstanceField, self).__init__(address=address, program=program, reference_value=None, obj_value=obj_value)
        self.field = field
    
    def __str__(self):
        return "ObjectReferenceInstanceField({address} in {program}, {obj_value}, {field})".format(address=self.address, obj_value=self.obj_value, field=self.field, program=self.program.getName(),)
        
    # TODO equality - same base reference for parent object + same field
        
class ObjectReferenceStaticField(ObjectReferenceBase):
    """ An object reference to an object pulled out of a static field """
    field = None
    def __init__(self, address, program, obj_value, field):
        super(ObjectReferenceStaticField, self).__init__(address=address, program=program, reference_value=None, obj_value=obj_value)
        self.field = field # TODO equality - match on field string
        
    def __str__(self):
        return "ObjectReferenceStaticField({address} in {program}, {obj_value}, {field})".format(address=self.address, obj_value=self.obj_value, field=self.field, program=self.program.getName(),)

class ObjectReferenceResult(ObjectReferenceBase):
    """ An object reference to an object returned from a call.
        May need to be updated with model output, or linked to an arg if there's a return self or similar
    """
    def __init__(self, address,program, obj_value):
        super(ObjectReferenceResult, self).__init__(address=address, program=program, reference_value=None, obj_value=obj_value)
    
    def __str__(self):
        return "ObjectReferenceResult({address} in {program}, {obj_value})".format(address=self.address, obj_value=self.obj_value, program=self.program.getName())
    
    ## TODO equality! need to record program
        
        
        
class ObjectValue(SymbolicValue):
    """ The value is an object, which can maintain internal state, and may have a previous object it was modified from """
    state = None
    type = None
    operations = None
    prev_object = None

    def __init__(self, type=None):            
        # todo pick most specific type out of previous_object.type or type
        self.type=type
        self.state = dict()
        self.operations = list()
        
    def __str__(self):
        return "ObjectValue({state})".format(state=self.state)
        
    """cases
        objectinit
            state = {}
            type = init (should always be the lowest possible type)
        objectmodifiedfield
            state[field] = value
            if class type reference is lower than type, update
        objectmodifiedbycall
            if invoke-virtual/direct type reference is lower than type, update
                (if invoke-virtual and reference is higher, check if there's a method
            
        
            can resolve
                state.update(call.resolve(arg_value).state)
            can't resolve
                assume doesn't modify state from what we know
            
            can resolve, not actually modified
            state = state
    maintain operations list """
    
 

class ObjectInit(ObjectValue):
    """ The value is an object, which has just been initialized """
    create_addr = None
    program = None
     
    def __init__(self, create_addr, program, type):       
        self.create_addr = create_addr
        self.program = program
        super(ObjectInit, self).__init__(type=type)
        
    def __str__(self):
        return "ObjectInit({create_addr} in {program}, {type}, {state})".format(create_addr=self.create_addr, program=self.program.getName(), type=self.type, state=self.state)
        
    def resolve(self, loop_stack=None):
        # can't resolve an object init further
        return self       
        
class ObjectModifiedField(ObjectValue):
    """ The value is an object where someone's set a field to something """
    create_addr = None
    program = None
    
    def __init__(self, create_addr, program, field, value):       
        self.create_addr = create_addr
        self.program = program
        self.field = field
        self.value = value
        
        super(ObjectModifiedField, self).__init__(type=field.clazz)
        
    def __str__(self):
        return "ObjectModifiedField({create_addr} in {program}, {type}, {field}={value})".format(create_addr=self.create_addr, program=self.program.getName(), type=self.type, field=self.field, value=self.value)    
        
    def perform(self, prev_object):
        """ return a new object that reflects this change applied to a previous object """
        
        new_obj = ObjectValue(type=self.type) # TODO pick the type of the prev object or this one
    
        new_obj.prev_object = prev_object
    
        if isinstance(prev_object, ObjectValue):
            # copy the previous list of operations
            new_obj.operations.extend(prev_object.operations)
            # copy the previous state
            new_obj.state.update(prev_object.state)
        else:
            # it's probably an ArgValue starting out the chain
            new_obj.operations.append(prev_object)
         
        new_obj.operations.append(self)
        #  add our field to the state
        new_obj.state[str(self.field)] = self.value        
        
        return new_obj
            
class ObjectModifiedByCall(ObjectValue):
    """ The value is an object which has been modified as an argument/this in a call"""
    call = None
    create_addr = None
    params_idx = None
    args_reg = None
    
    # args idx -1 = target object/this
    def __init__(self, call, params_idx, args_reg):
        self.call = call
        self.create_addr = call.addr
        
        self.args_reg = args_reg

        self.params_idx = params_idx
        type = None
        if params_idx == -1: #this
            type = call.dex_method.clazz
        else:
            type = call.dex_method.method_prototype.parameters[params_idx]
        super(ObjectModifiedByCall, self).__init__(type=type)
        
        
    def __str__(self):
        return "ObjectModifiedByCall({create_addr}, {type}, {call}, {state})".format(create_addr=self.create_addr, type=self.type, call=self.call, state=self.state)

    # TODO UNUSED?
    def resolve(self, loop_stack=None):

        resolve = self.call.resolve(loop_stack)
    
        if isinstance(resolve,dict):
            if self.args_reg in resolve:
                return resolve[self.args_reg]
        
        return self

    def perform(self, prev_object):
        """ return a new object that reflects this change applied to a previous object """
        
        new_obj = ObjectValue(type=self.type) # TODO pick the type of the prev object or this one
    
        new_obj.prev_object = prev_object
        
        if isinstance(prev_object, ObjectValue):
            # copy the previous list of operations
            new_obj.operations.extend(prev_object.operations)
            # copy the previous state
            new_obj.state.update(prev_object.state)
        else:
            # it's probably an ArgValue starting out the chain
            new_obj.operations.append(prev_object)
            
        # add ourselves to the operations
        new_obj.operations.append(self)
        
        
        
        # WIPTODO try to run the call
        if "__call__" not in new_obj.state:
            new_obj.state["__call__"] = list()
        new_obj.state["__call__"].append(self)
        """
        resolve = self.call.resolve()
        if isinstance(resolve,dict):
            if self.args_reg in resolve:
                # modified, so 
                resolve[self.args_reg]
        """
        
        return new_obj
        
class ObjectModelled(ObjectValue):
    """ The value is an object, which has been generated by one of our modelled functions """
     
    def __init__(self, call, type=None):       
        self.call = call
        self.create_addr = call.addr
        
        super(ObjectModelled, self).__init__(type=type) # TODO how handle obj reference?
        
    def __str__(self):
        return "ObjectModelled({create_addr}, {type}, {call}, {state})".format(create_addr=self.create_addr, type=self.type, call=self.call, state=self.state, chunk_trace=None)
        
    def resolve(self, loop_stack=None):
        # modelled objects should already be fully resolved?
        return self      
    
class DataValue(SymbolicValue):
    """ The value comes from some global data source, or an index in an array, and need some further resolution"""
    data_value_info = None

    # todo preprocess? what's useful here? (different for array, field?)
    def __init__(self, data_value_info):
        self.data_value_info = data_value_info

    def __str__(self):
        return "DataValue({})".format(self.data_value_info)
        
    def resolve(self, loop_stack=None):
        """ can't resolve a data value further atm """
        return self
        
class InstanceFieldValue(DataValue):
    """ The value comes from a field in an object, and need some further resolution"""
    field = None
    addr = None
    object = None
    program=None

    def __init__(self, addr, program, field, object):
        self.field = field
        self.addr = addr
        self.object = object
        self.program = program

    def __str__(self):
        return "InstanceFieldValue({address} in {program}, {clazz}.{field}, {type} from {obj})".format(address=self.addr, program=self.program.getName(), clazz=self.field.clazz, field=self.field.name, type=self.field.type, obj=self.object)
        
    def resolve(self, loop_stack=None):
        """ can't resolve an instance field value further atm """
        return self
        
class StaticFieldValue(DataValue):
    """ The value comes from a static field, and need some further resolution"""
    field = None
    addr = None
    program = None

    def __init__(self, addr, program, field):
        self.field = field
        self.addr = addr
        self.program = program

    def __str__(self):
        return "StaticFieldValue({address} in {program}, {clazz}.{field}, {type})".format(address=self.addr,program=self.program.getName(), clazz=self.field.clazz, field=self.field.name, type=self.field.type)
        
    def resolve(self, loop_stack=None):
        """ can't resolve a static field value further atm """
        return self

class Loop(SymbolicValue):
    """ The value is derived from operations that loop back around. Need to be careful about linking and resolution."""
    head = None # the codeblock at the top of the root
    tail = None # the codeblock at the bottom of the loop (that jumps back to the top)
    value = None # the value we're interested in, from the tail
    
    def __init__(self, head_addr, tail_addr, value):
        self.head = ghidra_utils.get_basic_block_at_address(head_addr)
        self.tail = ghidra_utils.get_basic_block_at_address(tail_addr)
        self.value = value
        
    def __str__(self):
        return "LoopValue({head}<--{tail},{value})".format(head=self.head, tail=self.tail, value=self.value)
        
    def resolve(self, loop_stack=None):
        # check if we're in the stack
        if loop_stack is not None:
            if self in loop_stack:
                """ note: simple assumption is that we're at top of the stack. But possible to have a case where we're not if we involve multiple variables
                    consider a loop where v3 is affected by v2, and both are modified in the loop. we'll loop over v3, see the v2 involvement, and loop over that before eventually finding the same loop again.
                    
                    TODO would be nice to have loops handle multiple regs at the same time, to simplify
                """
        
                # expected, saw ourselves. stop looping and return None. The multivalue containing the loop will catch that and remove from its list of values (assumption: every loop only occurs in the context of a multivalue with values fed to the top of the loop - otherwise, the value would be undefined in the first run of the loop).
                return None
        else:
            # no loop stack, create one
            loop_stack = list()
            
        # okay, didn't find ourself in the loop stack - add ourselves to the list, ask for a resolve, then remove ourself once it comes back
        loop_stack.append(self)
        
        res_val = self.value.resolve(loop_stack)
        
        #expect to be at the top of the stack when it comes back
        if loop_stack[-1] != self:
            raise Exception("Ooops? Loop stack didn't return with right loop at the top")
            
        loop_stack.pop()
        
        return res_val

class OutOfChunkValue(Value):
    """ The value comes from outside a single code chunk - this container allows us to temporarily handle that, until we can identify the right values. Shouldn't show up once values identified."""
    reg = None
    chunk = None
    value = None

    def __init__(self, reg, chunk): 
        self.reg = reg
        self.chunk = chunk

    def __str__(self): 
        if self.value is None:
            return "OutOfChunkValue({}, {})".format(self.reg, self.chunk)
        else:
            return str(self.value)
        
    def resolve(self, loop_stack=None):
        if self.value is None:
            raise Exception("Resolving unlinked OutOfChunkValue")
            
        return self.value.resolve(loop_stack)
            
    
        
class OutOfCodeBlockValue(Value):
    """ The value comes from outside a single code block - this container allows us to temporarily handle that, until we can identify the right values. Shouldn't show up once values identified. """
    reg = None
    code_block = None
    link_cache = None
    value = None

    def __init__(self, reg, block): # TODO can we avoid duplicate out of code blocks?
        self.reg = reg
        self.code_block = block

    def __str__(self): 
        if self.value is None:
            return "OutOfCodeBlockValue({}, {})".format(self.reg, self.code_block)
        else:
            return str(self.value)            
        
    def resolve(self, loop_stack=None):
        if self.value is None:
            raise Exception("Resolving unlinked OutOfCodeBlockValue")
            
        return self.value.resolve(loop_stack)
    
