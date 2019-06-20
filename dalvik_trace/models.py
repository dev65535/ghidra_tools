""" 

Implementation of models for dalvik functions """


import re
import dextypes
import values

# give all our model fields a prefix to minimise chance of collisions with real names
MODEL_FIELD_PREFIX = "_model_"
STRINGBUILDER_STATE= MODEL_FIELD_PREFIX+"str_chunks"
FILE_STATE = MODEL_FIELD_PREFIX+"filename"

RETURN="return"


def model_StringBuilder_init(call, resolved_this, resolved_params_list):
    resolve_dict = dict()
    
    obj_list = None
    if isinstance(resolved_this.value, values.MultiValue):
        obj_list = resolved_this.value.assignment_list
    else:
        obj_list = [resolved_this.value]
        
    for obj in obj_list:
        if not isinstance(obj, values.ObjectValue):
            raise Exception("Not an object value! {} - {}".format(obj, type(obj)))
    
        obj.state[STRINGBUILDER_STATE] = list()
        
        if re.match("Ljava/lang/StringBuilder;\.<init>\(I\)V", str(call.dex_method)) is None: # ignore the integer capacity init
            # any further params are just appends
            for param in resolved_params_list:
                obj.state[STRINGBUILDER_STATE].append(param.value)
        
    if len(obj_list) > 1:
        obj = values.MultiValue(obj_list)
    else:
        obj = obj_list[0]
        
    resolve_dict[resolved_this.reg] = obj
    resolve_dict[RETURN] = obj

    return resolve_dict
    
def model_String_init(call, resolved_this, resolved_params_list):
    resolve_dict = dict()
    
    # first param is the string
    obj_list = None
    if isinstance(resolved_params_list[0].value, values.MultiValue):
        obj_list = resolved_params_list[0].value.assignment_list
    else:
        obj_list = [resolved_params_list[0].value]
        
    if len(obj_list) > 1:
        obj = values.MultiValue(obj_list)
    else:
        obj = obj_list[0]
        
    resolve_dict[resolved_params_list[0].reg] = obj
    resolve_dict[RETURN] = obj

    return resolve_dict

def model_StringBuilder_append(call, resolved_this, resolved_params_list):
    resolve_dict = dict()
    
    obj_list = None
    if isinstance(resolved_this.value, values.MultiValue):
        obj_list = resolved_this.value.assignment_list
    else:
        obj_list = [resolved_this.value]
        
    for obj in obj_list:
        if not isinstance(obj, values.ObjectValue):
            raise Exception("Not an object value! {}".format(obj))
    
        for param in resolved_params_list:
            if isinstance(param.value, values.ObjectValue) and STRINGBUILDER_STATE in param.value.state:
                obj.state[STRINGBUILDER_STATE].extend(param.value.state[STRINGBUILDER_STATE])
            else:
                obj.state[STRINGBUILDER_STATE].append(param.value)
    
    if len(obj_list) > 1:
        obj = values.MultiValue(obj_list)
    else:
        obj = obj_list[0]
        
    resolve_dict[resolved_this.reg] = obj
    resolve_dict[RETURN] = obj        
        
    return resolve_dict

def model_StringBuilder_toString(call, resolved_this, resolved_params_list):
    resolve_dict = dict()
    
    obj_list = None
    if isinstance(resolved_this.value, values.MultiValue):
        obj_list = resolved_this.value.assignment_list
    else:
        obj_list = [resolved_this.value]
       
    val_list = list()
        
    for obj in obj_list:
        if not isinstance(obj, values.ObjectValue):
            raise Exception("Not an object value! {}".format(obj))
    
        built_string = list()
    
        for idx, chunk in enumerate(obj.state[STRINGBUILDER_STATE]):
            if isinstance(chunk, values.Value):
                # need to add some print markers
                #if idx != 0:
                #    built_string += " + "
                built_string.append(chunk)
            else:
                # string
                #if idx != 0:
                #    if isinstance(obj.state[STRINGBUILDER_STATE][idx-1], Value):
                #        # previous chunk was not a string - add a plus
                #        built_string += " + "
                built_string.append(chunk)
    
    
        val_list.append(values.AppendValue(built_string, "Ljava/lang/String;"))
    
    if len(val_list) > 1:
        val = values.MultiValue(val_list)
    else:
        val = val_list[0]
        
    resolve_dict[RETURN] = val
    
    return resolve_dict
    
def model_String_concat(call, resolved_this, resolved_params_list):
    resolve_dict = dict()
    
    str_list = None
    if isinstance(resolved_this.value, values.MultiValue):
        str_list = resolved_this.value.assignment_list
    else:
        str_list = [resolved_this.value]
       
    val_list = list()
        
    for s in str_list:
        if isinstance(s, dextypes.dex_string):
            s = str(s)
    
        if not isinstance(s, str):
            raise Exception("Not a string! {} - {}".format(s, type(s)))
        
        if isinstance(resolved_params_list[0].value, values.MultiValue):
            for concat in resolved_params_list[0].value.assignment_list:
                val_list.append(values.AppendValue([s, concat], "Ljava/lang/String;"))
        else:
            val_list.append(values.AppendValue([s, resolved_params_list[0].value], "Ljava/lang/String;"))
    
    if len(val_list) > 1:
        val = values.MultiValue(val_list)
    else:
        val = val_list[0]
        
    resolve_dict[RETURN] = val
    
    return resolve_dict
    
def model_String_toLowerCase(call, resolved_this, resolved_params_list):
    resolve_dict = dict()
    
    str_list = None
    if isinstance(resolved_this.value, values.MultiValue):
        str_list = resolved_this.value.assignment_list
    else:
        str_list = [resolved_this.value]
       
    val_list = list()
        
    for s in str_list:
        if not isinstance(s, str):
            raise Exception("Not a string! {}".format(s))
        
        val_list.append(s.lower())
    
    if len(val_list) > 1:
        val = values.MultiValue(val_list)
    else:
        val = val_list[0]
        
    resolve_dict[RETURN] = val
    
    return resolve_dict
    
def model_File_init(call, resolved_this, resolved_params_list):
    resolve_dict = dict()
    
    obj_list = None
    if isinstance(resolved_this.value, values.MultiValue):
        obj_list = resolved_this.value.assignment_list
    else:
        obj_list = [resolved_this.value]
        
    for obj in obj_list:
        if not isinstance(obj, values.ObjectValue):
            raise Exception("Not an object value! {}".format(obj))
    
        obj.state[FILE_STATE] = values.AppendValue([], type=None)
    
        for param in resolved_params_list:
            if isinstance(param.value, values.ObjectValue) and FILE_STATE in param.value.state:
                obj.state[FILE_STATE].extend(param.value.state[FILE_STATE])
            else:
                obj.state[FILE_STATE].append(param.value) 
    
    if len(obj_list) > 1:
        obj = values.MultiValue(obj_list)
    else:
        obj = obj_list[0]
        
    resolve_dict[resolved_this.reg] = obj
    
    return resolve_dict
    
def model_File_getAbsolutePath(call, resolved_this, resolved_params_list):
    resolve_dict = dict()
    
    obj_list = None
    if isinstance(resolved_this.value, values.MultiValue):
        obj_list = resolved_this.value.assignment_list
    else:
        obj_list = [resolved_this.value]
        
    ret_list = []
        
    for obj in obj_list:
        if isinstance(obj, values.ObjectValue) and FILE_STATE in obj.state:
            ret_list.append(obj.state[FILE_STATE])
        else:
            ret_list.append(obj)
    
    if len(ret_list) > 1:
        ret = values.MultiValue(ret_list)
    else:
        ret = ret_list[0]
        
    resolve_dict[RETURN] = ret
    
    return resolve_dict
   
def model_File_getAbsoluteFile(call, resolved_this, resolved_params_list):
    path_result = model_File_getAbsolutePath(call, resolved_this, resolved_params_list)[RETURN]
    
    obj = values.ObjectModelled(call=call, type="Ljava/io/File;")
    obj.state[FILE_STATE] = values.AppendValue([], type=None)
    
    if isinstance(path_result, values.ObjectValue) and FILE_STATE in path_result.state:
        obj.state[FILE_STATE].extend(path_result.state[FILE_STATE])
    else:
        obj.state[FILE_STATE].append(path_result)
    
    resolve_dict= {RETURN: obj}
        
    return resolve_dict
   
def model_File_getPath(call, resolved_this, resolved_params_list):   
    # TODO - cheating here, but should be close enough
    return model_File_getAbsolutePath(call, resolved_this, resolved_params_list)

def model_File_getName(call, resolved_this, resolved_params_list):   
    # TODO - cheating here, but should be close enough
    return model_File_getAbsolutePath(call, resolved_this, resolved_params_list)    
    
    
def model_File_getParentFile(call, resolved_this, resolved_params_list):
    resolve_dict = dict()
    
    obj_list = None
    if isinstance(resolved_this.value, values.MultiValue):
        obj_list = resolved_this.value.assignment_list
    else:
        obj_list = [resolved_this.value]
        
    ret_list = []
        
    for obj in obj_list:
        if not isinstance(obj, values.ObjectValue):
            ret_list.append("Parent({})".format(obj))
        else:       
            ret_list.append("Parent({})".format(obj.state[FILE_STATE]))
    
    if len(ret_list) > 1:
        ret = values.MultiValue(ret_list)
    else:
        ret = ret_list[0]
        
    resolve_dict[RETURN] = ret
    
    return resolve_dict

def model_Context_getDir(call, resolved_this, resolved_params_list):
    resolve_dict = dict()

    obj = values.ObjectModelled(call=call, type="Ljava/io/File;")
    obj.state[FILE_STATE] = values.AppendValue(["<CONTEXT_DIR>"], type="Ljava/lang/String;")

    name_param = resolved_params_list[0]
    obj.state[FILE_STATE].append(name_param.value) 
                
    resolve_dict[RETURN] = obj
    
    return resolve_dict
    
def model_Context_getCacheDir(call, resolved_this, resolved_params_list):
    resolve_dict = dict()

    obj = values.ObjectModelled(call=call, type="Ljava/io/File;")
    obj.state[FILE_STATE] = values.AppendValue(["<CONTEXT_CACHE_DIR>"], type="Ljava/lang/String;")

    name_param = resolved_params_list[0]
    obj.state[FILE_STATE].append(name_param.value) 
                
    resolve_dict[RETURN] = obj
    
    return resolve_dict
    
def model_Environment_getExternalStorageDirectory(call, resolved_this, resolved_params_list):
    resolve_dict = dict()

    obj = values.ObjectModelled(call=call, type="Ljava/io/File;")
    obj.state[FILE_STATE] = values.AppendValue(["<ExternalStorageDirectory>"], type="Ljava/lang/String;")

    resolve_dict[RETURN] = obj
    
    return resolve_dict
    
    
    
    
class CallEffects(object):
    target_object_modified  = None
    params_modified = None # list of affected params, by index (so 0 is the first param [not counting the this object])
    other_effects = None # dictionary of other types of effects
    
    def __init__(self, modified_param_list=None, target_object_modified=False, **kwargs):
        self.other_effects = kwargs
        if modified_param_list is None:
            modified_param_list = []
    
        self.params_modified = modified_param_list
        self.target_object_modified = target_object_modified
        
    def is_param_modified(self, idx):
        return idx in self.params_modified
        
    def __str__(self):
        return "CallEffects(target_modified={}, params_modified={}, {})".format(self.target_object_modified, self.params_modified, self.other_effects)
        
        
class Model(object):
    matcher = None # regex string to match against
    effects = None # call effects for what objects/params are modified
    model_func = None # function to model the call
    
    def __init__(self, matcher, effects, model_func=None):
        self.matcher = matcher
        self.effects = effects
        self.model_func = model_func
        
    def model(self, call, resolved_this, resolved_params_list):
        if self.model_func is not None:
            return self.model_func(call, resolved_this, resolved_params_list)
        
        return None
        
    def match(self, dex_method):
        return re.match(self.matcher, str(dex_method)) is not None
            
MODEL_LIST = [ 
    # Java Strings
    Model(matcher="Ljava/lang/StringBuilder;\.<init>\(.*\)V", effects=CallEffects(target_object_modified=True), model_func=model_StringBuilder_init),
    Model(matcher="Ljava/lang/StringBuilder;\.append\(.*\)Ljava/lang/StringBuilder;", effects=CallEffects(target_object_modified=True), model_func=model_StringBuilder_append),
    Model(matcher="Ljava/lang/StringBuilder;\.toString\(\)Ljava/lang/String;", effects=CallEffects(target_object_modified=False), model_func=model_StringBuilder_toString),
    Model(matcher="Ljava/lang/String;\.concat\(Ljava/lang/String;\)Ljava/lang/String;", effects=CallEffects(target_object_modified=False), model_func=model_String_concat),
    Model(matcher="Ljava/lang/String;\.toLowerCase\(\)Ljava/lang/String;", effects=CallEffects(target_object_modified=False), model_func=model_String_toLowerCase),
    Model(matcher="Ljava/lang/String;\.startsWith\(Ljava/lang/String;\)Z", effects=CallEffects(target_object_modified=False), model_func=None), # TODO
    Model(matcher="Ljava/lang/String;\.length\(\)I", effects=CallEffects(target_object_modified=False), model_func=None), # TODO
    Model(matcher="Ljava/lang/String;\.equals\(.*\)Z", effects=CallEffects(target_object_modified=False), model_func=None), # TODO
    Model(matcher="Ljava/lang/String;\.indexOf\(.*\)I", effects=CallEffects(target_object_modified=False), model_func=None), # TODO
    Model(matcher="Ljava/lang/String;\.trim\(\)Ljava/lang/String;", effects=CallEffects(target_object_modified=False), model_func=None), # TODO
    Model(matcher="Ljava/lang/String;\.<init>\(Ljava/lang/String;\)V", effects=CallEffects(target_object_modified=True), model_func=model_String_init),
 
    
    # Java Files
    Model(matcher="Ljava/io/File;.<init>\(.*\)V", effects=CallEffects(target_object_modified=True), model_func=model_File_init),
    Model(matcher="Ljava/io/File;.getAbsolutePath\(\)Ljava/lang/String;", effects=CallEffects(target_object_modified=False), model_func=model_File_getAbsolutePath),
    Model(matcher="Ljava/io/File;.getAbsoluteFile\(\)Ljava/io/File;", effects=CallEffects(target_object_modified=False), model_func=model_File_getAbsoluteFile), 
    Model(matcher="Ljava/io/File;.getPath\(\)Ljava/lang/String;", effects=CallEffects(target_object_modified=False), model_func=model_File_getPath),
    Model(matcher="Ljava/io/File;.getName\(\)Ljava/lang/String;", effects=CallEffects(target_object_modified=False), model_func=model_File_getName),
    Model(matcher="Ljava/io/File;.getParentFile\(\)Ljava/io/File;", effects=CallEffects(target_object_modified=False), model_func=model_File_getParentFile),
    Model(matcher="Ljava/io/File;.createNewFile\(\)Z", effects=CallEffects(target_object_modified=False, disk_write=True, file_create=True), model_func=None),
    Model(matcher="Ljava/io/File;.mkdir\(\)Z", effects=CallEffects(target_object_modified=False, disk_write=True, file_create=True), model_func=None),
    Model(matcher="Ljava/io/File;.mkdirs\(\)Z", effects=CallEffects(target_object_modified=False, disk_write=True, file_create=True), model_func=None),
    Model(matcher="Ljava/io/File;.exists\(\)Z", effects=CallEffects(target_object_modified=False), model_func=None),
    Model(matcher="Ljava/io/File;.isDirectory\(\)Z", effects=CallEffects(target_object_modified=False), model_func=None),        
    Model(matcher="Ljava/io/File;.length\(\)J", effects=CallEffects(target_object_modified=False), model_func=None),        
    Model(matcher="Ljava/io/File;.listFiles\(\)\[Ljava/io/File;", effects=CallEffects(target_object_modified=False), model_func=None),  
    Model(matcher="Ljava/io/File;.isFile\(\)Z", effects=CallEffects(target_object_modified=False), model_func=None),            
    Model(matcher="Ljava/io/File;.delete\(\)Z", effects=CallEffects(target_object_modified=False, disk_write=True), model_func=None),            
    Model(matcher="Ljava/io/FileInputStream;.<init>\(.*\)V", effects=CallEffects(target_object_modified=False), model_func=None),       
    
    # Java collections
    Model(matcher="Ljava/util/ArrayList;\.add\(Ljava/lang/Object;\)Z", effects=CallEffects(target_object_modified=True), model_func=None),      
    Model(matcher=r"Ljava/lang/Integer;\.valueOf\(I\)Ljava/lang/Integer;", effects=CallEffects(target_object_modified=False), model_func=None),
    Model(matcher=r"Ljava/util/HashMap;\.<init>\(I\)V", effects=CallEffects(target_object_modified=True), model_func=None),
    Model(matcher=r"Ljava/util/HashMap;\.put\(Ljava/lang/Object;,Ljava/lang/Object;\)Ljava/lang/Object;", effects=CallEffects(target_object_modified=True), model_func=None),

    # Android
    Model(matcher=r"Landroid/content/Context;\.getDir\(Ljava/lang/String;,I\)Ljava/io/File;", effects=CallEffects(target_object_modified=False), model_func=model_Context_getDir),
    Model(matcher=r"Landroid/content/Context;\.getCacheDir\(Ljava/lang/String;,I\)Ljava/io/File;", effects=CallEffects(target_object_modified=False), model_func=model_Context_getCacheDir),
    Model(matcher=r"Landroid/os/Environment;\.getExternalStorageDirectory\(\)Ljava/io/File;", effects=CallEffects(target_object_modified=False), model_func=model_Environment_getExternalStorageDirectory),Model(matcher=r"Landroid/text/TextUtils;\.isEmpty\(.*\)Z", effects=CallEffects(target_object_modified=False), model_func=None),    
    Model(matcher=r"Landroid/net/Uri;\.parse\(Ljava/lang/String;\)Landroid/net/Uri;", effects=CallEffects(target_object_modified=False), model_func=None), # TODO

    
    ]
    
def find_model(dex_method):
    # TODO improve this
    for m in MODEL_LIST:
        if m.match(dex_method):
            return m
    return None
    


