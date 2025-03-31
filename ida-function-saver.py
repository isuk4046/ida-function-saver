import idaapi
import idautils
import idc

class FunctionSaverPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Function Typedef Generator"
    help = "Generates typedefs and function pointers for selected functions"
    wanted_name = "Function Typedef Generator"
    wanted_hotkey = "Alt-c"
    
    def init(self):
        print("Function Typedef Generator plugin initialized. Press Alt-c to use.")
        return idaapi.PLUGIN_KEEP
    
    def run(self, arg):
        copy_function_to_clipboard()
        
    def term(self):
        pass

def get_function_name(ea):
    """Get the name of the function containing the given address"""
    return idc.get_func_name(ea)

def parse_function_type(func_type_str):
    """Parse a function type string to extract return type and arguments"""
    #if not func_type_str:
        #return "__int64", ["__int64 a1", "__int64 a2"]
    
    # Extract return type and calling convention
    parts = func_type_str.split("(")
    first_part = parts[0].strip()
    
    # Check if there's a calling convention in the type
    cc_keywords = ["__cdecl", "__stdcall", "__fastcall", "__thiscall", "__vectorcall", "__pascal"]
    ret_type = first_part
    extracted_cc = None
    
    for cc in cc_keywords:
        if cc in first_part:
            # Extract the calling convention from the return type
            ret_type = first_part.replace(cc, "").strip()
            extracted_cc = cc
            break
    
    if not ret_type or ret_type == "unknown":
        ret_type = "__int64"
    
    # Extract arguments
    args = []
    try:
        # Find the part between parentheses
        args_start = func_type_str.find('(')
        args_end = func_type_str.rfind(')')
        if args_start != -1 and args_end != -1:
            args_str = func_type_str[args_start+1:args_end].strip()
            
            if args_str and args_str.lower() != "void":
                # Split by commas, but be careful with types that include commas
                depth = 0
                current_arg = ""
                for char in args_str:
                    if char == '(' or char == '<':
                        depth += 1
                        current_arg += char
                    elif char == ')' or char == '>':
                        depth -= 1
                        current_arg += char
                    elif char == ',' and depth == 0:
                        args.append(current_arg.strip())
                        current_arg = ""
                    else:
                        current_arg += char
                
                if current_arg:
                    args.append(current_arg.strip())
            
                # Process each argument to separate type from name
                processed_args = []
                for i, arg in enumerate(args):
                    parts = arg.split()
                    if len(parts) > 1:
                        # If there's a variable name, use it
                        arg_name = parts[-1]
                        if arg_name.startswith('*'):
                            # Handle pointer to variable
                            arg_type = ' '.join(parts[:-1]) + '*'
                            arg_name = arg_name[1:]
                        else:
                            # Normal case
                            arg_type = ' '.join(parts[:-1])
                    else:
                        # No variable name, just a type
                        arg_type = arg
                        arg_name = f"a{i+1}"
                    
                    processed_args.append(f"{arg_type} {arg_name}")
                
                return ret_type, extracted_cc, processed_args
    except:
        pass
        
    return ret_type, extracted_cc, []
    
    # Default
    #return ret_type, extracted_cc, [f"__int64 a{i+1}" for i in range(2)]

def get_function_signature(func_addr):
    """Get function signature from IDA"""
    # Try to get function type from IDA
    func_type = idc.get_type(func_addr)
    
    if not func_type:
        # Try to use tinfo if available
        try:
            tif = idaapi.tinfo_t()
            if idaapi.get_tinfo(tif, func_addr):
                func_type = str(tif)
        except:
            pass
    
    # Parse the function type
    ret_type, extracted_cc, args = parse_function_type(func_type)
    
    # Get the calling convention (use extracted one or default)
    cc = extracted_cc if extracted_cc else "__fastcall"  # Default for x64
    
    return ret_type, cc, args

def get_function_typedef_and_pointer(func_addr):
    """Generate typedef and function pointer for the selected function"""
    func_name = get_function_name(func_addr)
    
    # Get function signature details
    ret_type, cc, args = get_function_signature(func_addr)
    
    # Join arguments into a string
    args_str = ", ".join(args)
    
    # Generate typedef (Only one calling convention)
    typedef = f"typedef {ret_type}({cc}* {func_name}_t)({args_str});"
    # Generate function pointer
    func_ptr = f"{func_name}_t {func_name}_o;"
    
    return typedef, func_ptr

def copy_function_to_clipboard():
    """Copy the current function's typedef and pointer to clipboard"""
    try:
        import pyperclip
    except ImportError:
        print("Error: pyperclip module not installed. Install it using:")
        print("pip install pyperclip")
        return
    
    ea = idc.get_screen_ea()
    func = idaapi.get_func(ea)
    if not func:
        print("Error: Please position the cursor within a function.")
        return
    
    func_addr = func.start_ea
    typedef, func_ptr = get_function_typedef_and_pointer(func_addr)
    
    if typedef and func_ptr:
        # Copy to clipboard
        content = f"{typedef}\n{func_ptr}"
        pyperclip.copy(content)
        
        # Display a small popup message
        func_name = get_function_name(func_addr)
        idaapi.msg(f"Copied {func_name} to clipboard!\n")

def save_selected_function():
    """Save the currently selected function in the requested format"""
    ea = idc.get_screen_ea()
    func = idaapi.get_func(ea)
    if not func:
        print("Please position the cursor within a function.")
        return
    
    func_addr = func.start_ea
    typedef, func_ptr = get_function_typedef_and_pointer(func_addr)
    
    if typedef and func_ptr:
        print("\nFunction typedef and pointer generated:")
        print(typedef)
        print(func_ptr)
        
        # Copy to clipboard
        try:
            import pyperclip
            pyperclip.copy(f"{typedef}\n{func_ptr}")
            print("\nCopied to clipboard!")
        except ImportError:
            print("\nInstall pyperclip module to enable clipboard functionality.")
            
        # Save to a file
        file_path = idaapi.ask_file(1, "*.h", "Save function typedef and pointer")
        if file_path:
            with open(file_path, 'w') as f:
                f.write(f"{typedef}\n{func_ptr}\n")
            print(f"\nSaved to {file_path}")

# Register the plugin
def PLUGIN_ENTRY():
    return FunctionSaverPlugin()

# Add a helper function for users to manually set specific function signature
def save_with_custom_signature(ret_type="__int64", args=None, calling_convention="__fastcall"):
    """
    Save the currently selected function with custom signature
    
    Examples:
    save_with_custom_signature("int", ["const char* a1", "int a2"])
    save_with_custom_signature("void", ["HWND hWnd", "UINT message"], "__stdcall")
    """
    if args is None:
        args = ["__int64 a1", "__int64 a2"]
    
    ea = idc.get_screen_ea()
    func = idaapi.get_func(ea)
    if not func:
        print("Please position the cursor within a function.")
        return
    
    func_addr = func.start_ea
    func_name = get_function_name(func_addr)
    
    # Join arguments into a string
    args_str = ", ".join(args)
    
    # Generate typedef
    typedef = f"typedef {ret_type}({calling_convention}* {func_name}_t)({args_str});"
    # Generate function pointer
    func_ptr = f"{func_name}_t {func_name}_o;"
    
    print("\nFunction typedef and pointer generated:")
    print(typedef)
    print(func_ptr)
    
    # Copy to clipboard
    try:
        import pyperclip
        pyperclip.copy(f"{typedef}\n{func_ptr}")
        print("\nCopied to clipboard!")
    except ImportError:
        print("\nInstall pyperclip module to enable clipboard functionality.")
        
    # Save to a file
    file_path = idaapi.ask_file(1, "*.h", "Save function typedef and pointer")
    if file_path:
        with open(file_path, 'w') as f:
            f.write(f"{typedef}\n{func_ptr}\n")
        print(f"\nSaved to {file_path}")

# Register hotkey for stand-alone script usage
try:
    hotkey_ctx = idaapi.add_hotkey("Alt-c", copy_function_to_clipboard)
    if hotkey_ctx is None:
        print("Failed to register Alt-c hotkey.")
    else:
        print("Alt-c hotkey registered successfully.")
except:
    print("Could not register hotkey. You can still use the copy_function_to_clipboard() function manually.")

if __name__ == "__main__":
    print("\nFunction Typedef Generator")
    print("==========================")
    print("Usage:")
    print("1. Position cursor in a function")
    print("2. Press Alt-c to copy the function typedef and pointer to clipboard")
    print("3. Or run save_selected_function() to save to a file")
    print("\nIf the argument types are incorrect, you can manually set them by running:")
    print('save_with_custom_signature("return_type", ["arg1_type arg1_name", "arg2_type arg2_name"])')