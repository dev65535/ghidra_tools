""" 

implementation of call tracking for dalvik """

import values
import models
        
class ParamValue(object):
    # track a value set in a param and the reg it was passed in
    reg = None
    value = None
    
    def __init__(self, reg, value):
        self.reg = reg
        self.value = value
        
    def __str__(self):
        return "ParamValue({reg}, {value})".format(reg=self.reg, value=self.value)

    def __repr__(self):
        return self.__str__()  
        
    def resolve_value(self, loop_stack=None):
        """ resolve down to object value, if necessary """
        p_val = self.value.resolve(loop_stack)
        if isinstance(p_val, values.MultiValue):
            new_list = list()
            for pv in p_val.assignment_list:
                if isinstance(pv, values.ObjectReference):
                    pv = pv.resolve_to_object_value()
                new_list.append(pv)
            p_val.assignment_list = new_list
        elif isinstance(p_val, values.ObjectReference):
            p_val = p_val.resolve_to_object_value()
            
        return p_val
        
        
class Call(values.Value):
    insn = None
    addr = None
    dex_method = None
    model = None
    params_list = None
    this = None
    program = None

    def __init__(self, insn, dex_method, this=None, params_list=None):
        self.insn = insn
        self.addr = self.insn.getAddress()
        self.program = self.insn.getProgram()
        self.dex_method = dex_method
        self.model = models.find_model(dex_method)
        self.this = this
        self.params_list = params_list      

    def __str__(self):
        return "Call({address} in {program}, {clazz}.{name}())".format(address=self.addr, program=self.program.getName(), clazz=self.dex_method.clazz, name=self.dex_method.name)

    def __repr__(self):
        return self.__str__()
        
    def is_static(self):
        return self.this is None
        
    def resolve_args(self, loop_stack=None):
        # resolve the argument values as much as possible
        resolved_params_list = list()
        if self.params_list is not None:
            for param in self.params_list:                        
                resolved_params_list.append(ParamValue(param.reg, param.resolve_value(loop_stack)))
            
        resolved_this = None
        if self.this is not None:
            resolved_this = ParamValue(self.this.reg, self.this.resolve_value(loop_stack))
            
        return resolved_this, resolved_params_list
        
    def resolve(self, loop_stack=None): #TODO implement depth # TODO pass in headers so we don't have to recreate the method dict everytime for the find_impls
        # possible - resolve could run model if we have one. if we don't remove the call, can later call symexec with a depth...
        resolved_this, resolved_params_list = self.resolve_args(loop_stack)
        
        resolve_dict = dict()
        
        # determine if we've got a model we know about
        if self.model is not None:
            resolve_dict = self.model.model(self, resolved_this, resolved_params_list)
        elif "interface" in self.insn.getMnemonicString():
            print("Can't resolve interface call {}".format(self))
        elif "super" in self.insn.getMnemonicString():
            print("Can't resolve super call {}".format(self))
        elif "virtual" in self.insn.getMnemonicString():
            print("Can't resolve virtual call {}".format(self))            
        else:                
            from dalvik_trace import FunctionTrace
            import find_calls
            impls = find_calls.find_impls(dex_method=self.dex_method, quiet=True)
            
            assert len(impls.keys()) ==1, "Unexpectedly too few/many impl keys"
            impl_list = impls[impls.keys()[0]]
            assert len(impl_list) ==1, "Unexpectedly too many impls"
            
            impl = impl_list[0]
            
            try:
                func_trace = FunctionTrace(impl)
                try:
                    resolve_dict = func_trace.sym_exec(self, resolved_this, resolved_params_list)
                except Exception as e:
                    print("Failed to symexec {} for {} - {}".format(impl, self, e))
            except Exception as e:
                print("Failed to trace {} for {} - {}".format(impl, self, e))
            
        return resolve_dict        
        
    def is_param_modified(self, idx):
        if self.model is not None:
            return self.model.effects.is_param_modified(idx)
            
        # if not modelled, assume any param is modified
        return True

    def is_target_modified(self):
        if self.model is not None:
            return self.model.effects.target_object_modified
            
        # if not modelled, assume the target is modified
        return True

        