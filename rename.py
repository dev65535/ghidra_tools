from collections import Counter

from __main__ import getState
import ghidra

import ghidra_utils


def get_function_strings(function):
    """ Get a list of all of the strings used by a function (including duplicates) """

    string_list = []

    program = function.getProgram()

    treemgr = program.getTreeManager()

    string_data_range = treemgr.getFragment(
        treemgr.getTreeNames()[0], "string_data")

    refs = ghidra_utils.get_references_for_function(function)

    for ref in refs:
        # don't care about flow references, only data
        if ref.getReferenceType().isData():
            # see if the ref dest is within the strings section
            address = ref.getToAddress()
            if string_data_range.contains(address):
                # yup, it's a string
                string_data = ghidra_utils.dictify(
                    address, program=program)["data"]

                # ignore the empty string/whitespace only
                string_data = string_data.strip()
                if string_data != "":
                    string_list.append(string_data)

    return string_list


def get_class_strings(class_name):
    """ Get a list of all of the strings used by functions in a class """

    string_list = []
    # TODO should we include internal classes "$"? - but not multiple levels of internal?
    for function in ghidra_utils.get_all_functions_for_class(class_name):
        string_list.extend(get_function_strings(function))

    return string_list


def split_class_name(class_name):
    """ Split a class name into a tuple containing list of package path elements and list of class name elements (e.g., [foo, a, b, 1] for foo$a$b$1, or [foo] for foo """
    name = ghidra_utils.SymbolDescriptor(class_name)
    package_elements = name.namespace
    class_elements = name.class_name.split("$")

    return (package_elements, class_elements)


def is_anonymous_class(class_name):
    """ Return true if this is an anonymous internal class """
    class_elements = split_class_name(class_name)[1]
    if len(class_elements) > 1:  # not single, is internal
        last_class_name = class_elements[-1]

        if last_class_name[0] in "0123456789":
            # first char of anonymous class is a number
            return True

    return False


def suggest_new_class_name(class_name):
    """ Suggest a new class name, based on the most common string used in the class (logging messages) """
    # TODO find all internal classes of this class, and use them to help generate suggestions
    if is_anonymous_class(class_name):
        # anonymous! leave this as is. (we'll just change the parent class)
        return None

    # get the list by count
    sorted_list = Counter(get_class_strings(class_name)).most_common()
    # pick the top contenders - take anything that has the same count as the the first in the list
    top_list = [element[0]
                for element in sorted_list if element[1] == sorted_list[0][1]]

    if not top_list:
        return None

    # remove bad chars
    BAD_CHARS = ":,/\\()[]$;#@!&^%*+'\""
    clean_top_list = []
    for top in top_list:
        for c in BAD_CHARS:
            top = top.replace(c,"")
        clean_top_list.append(top)
    top_list = clean_top_list
    
    # heuristics to pick between them - prefer things with dots, and things without " ", and things that aren't empty
    if len(top_list) > 1:
        dot_list = [guess for guess in top_list if "." in guess]
        if dot_list:
            top_list = dot_list

    if len(top_list) > 1:
        no_space_list = [guess for guess in top_list if " " not in guess]
        if no_space_list:
            top_list = no_space_list

    # preference longer name
    top_list.sort(key=len, reverse=True)
    #print(top_list)
    new_name = top_list[0]

    # if there's a dot, split the name and take the last chunk
    if "." in new_name:
        new_name = new_name.split(".")[-1]

    # if there's a space, split the name and take the first chunk
    if " " in new_name:
        new_name = new_name.split(" ")[0]

    # replace the old class name with this one
    # TODO handle internal classes (anonymous or otherwise)
    # should make sure, at minimum, they have the parent name in their symbol.
    package_elements, class_elements = split_class_name(class_name)

    class_elements[-1] = new_name
    new_name = "L" + "/".join(package_elements) + \
        "/" + "$".join(class_elements) + ";"

    return new_name.encode("utf-8")


def get_all_class_symbols_in_program(program=None, class_path=None):
    """ Return all the class symbols in the specified program (optionally limited by a given classpath) """
    if program is None:
        program = getState().getCurrentProgram()

    iterator_list = []
    if class_path is None:
        iterator_list.append(program.getSymbolTable().getDefinedSymbols())
    else:
        class_path = ghidra_utils.SymbolDescriptor(class_path).to_ghidra()
        namespaces = ghidra.app.util.NamespaceUtils.getNamespaces( class_path, None, program)
        if namespaces is not None:
            iterator_list.append(program.getSymbolTable().getSymbols(namespaces[0]))
        
    while iterator_list:
        symit = iterator_list.pop()
        for symbol in symit:
            if symbol.getSymbolType() == ghidra.program.model.symbol.SymbolType.CLASS:
                yield symbol
            elif symbol.getSymbolType() == ghidra.program.model.symbol.SymbolType.NAMESPACE:
                # if it's a namespace, get an iterator over it and add that to the list of iterators we're working through
                # ghidra namespacesymbols aren't namespaces, so gross conversion :/
                namespace = ghidra.app.util.NamespaceUtils.getNamespaces( symbol.getName(True), None, program)
                if namespace is not None:
                    iterator_list.append(program.getSymbolTable().getSymbols(namespace[0]))
                


PROGUARD_CUTOFF = 3  # names longer than this many characters probably aren't proguarded
# list of short terms that aren't actually proguarded
PROGUARD_EXCLUSIONS = ['app', 'com', 'ipc', 'jni', 'log', 'max',
                       'min', 'net', 'req', 'sdk', 'sum', 'ui', 'url', 'web', 'zip']


def is_proguarded(name):
    """ Return true if we think the last element in the name is proguarded
        e.g., last internal class name, class name, last package name 
    """
    if is_anonymous_class(name):
        return False

    # if this is actually a package, the last element will be in class elements anyway
    class_elements = split_class_name(name)[1]

    check_name = class_elements[-1]

    if len(check_name) > PROGUARD_CUTOFF:
        return False

    if check_name in PROGUARD_EXCLUSIONS:
        return False

    # probably proguarded
    return True

# namespaces we're not likely to care about
EXCLUDED_NAMESPACES = ["android::", "com::google::", "java::", "javax::", "junit::", "kotlinx::", "org::apache::", "org::json::", "org::w3c::"]

def suggest_new_names_for_all_classes_in_program(program=None, suggestions=None, class_path=None):
    """ Return a dictionary of name suggestions for classes in this program 

        Supply a dictionary of suggestions if we already have them to skip the classes they apply to
    """
    if suggestions is None:
        suggestions = dict()

    # handle if we've already named these...
    for class_symbol in get_all_class_symbols_in_program(class_path=class_path, program=program):
        old_name = class_symbol.getName(True)
        
        excluded = False
        for excluded_path in EXCLUDED_NAMESPACES:
            if old_name.startswith(excluded_path):
                # don't care, skip
                excluded = True
        if excluded:
            continue
                
        old_name = ghidra_utils.SymbolDescriptor(old_name).to_java()

        # only run this for classes where we haven't already got a suggestion (e.g., from a previous program)
        if old_name not in suggestions:
            # only do this for proguarded classes
            if is_proguarded(old_name):
                new_name = suggest_new_class_name(old_name)

                #print("{}->{}".format(old_name, new_name))
                suggestions[old_name] = new_name

    return suggestions

def suggest_new_names_for_all_classes(suggestions=None, class_path=None):
    """ Return a dictionary of name suggestions for all classes in all programs (optionally limited by
        part of a class path)

        Supply a dictionary of suggestions if we already have them to skip the classes they apply to (e.g., from previous runs)
    """
    if suggestions is None:
        suggestions = dict()

    for program in ghidra_utils.get_all_dex_programs():
        # ignore the return, this will also update the suggestions dictionary directly
        suggest_new_names_for_all_classes_in_program(
            program=program, suggestions=suggestions, class_path=class_path)

    return suggestions
