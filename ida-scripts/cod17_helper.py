# IDA - The Interactive Disassembler Version 7.7.220118 Windows x64 (64-bit address size)
# Python 3.10.7 (tags/v3.10.7:6cc6b13, Sep  5 2022, 14:08:36) [MSC v.1933 64 bit (AMD64)] on win32

import idautils, idc, idaapi, ida_xref, ida_name
import ida_helper

def elf_print_dvars(ea):
    for xref in idautils.XrefsTo(ea, 0):
        address = ida_helper.decode_ea(idc.next_head(xref.frm)).ops[1].addr
        string = idc.get_strlit_contents(address, -1, idc.STRTYPE_C)
        if string != None:
            print(string.decode())

def elf_print_lua_functions(ea):
    for xref in idautils.XrefsTo(ea, 0):
        address = ida_helper.decode_ea(idc.prev_head(idc.prev_head(idc.prev_head(xref.frm)))).ops[1].addr
        string = idc.get_strlit_contents(address, -1, idc.STRTYPE_C)
        if string == None:
            print(hex(xref.frm) + " has no string")
            continue
        print(string.decode())

def cod17_print_ecx(ea):
    for xref in idautils.XrefsTo(ea, 0):
        test = ida_helper.decode_ea(idc.prev_head(xref.frm)).ops[1].value
        print(str(test))

def hash(str):
    key = 0xCBF29CE484222325
    for i in range(len(str)):
        key = (0x100000001B3 * (ord(str[i].lower()) ^ key))
    key &= 0x7FFFFFFFFFFFFFFF
    return key

def cod17_rename_dvars(start, end, file):
    f = open(file)
    dvars = f.read().splitlines()
    f.close()
    
    i = 0
    for dvar in dvars:
        occurence = idaapi.find_binary(start, end, hex(hash(dvar)), 16, idaapi.SEARCH_DOWN)
        if occurence == idc.BADADDR:
            continue

        reference = ida_xref.get_first_dref_to(occurence)
        if reference == idc.BADADDR:
            print(hex(occurence) + " has no reference")
            continue

        ida_name.set_name(reference, dvar, ida_name.SN_NOCHECK | ida_name.SN_FORCE)
        print(dvar + " found and renamed")
        i += 1

    print(str(i) + "/4745 dvars resolved")

def cod17_rename_lua_functions(start, end, file):
    f = open(file)
    functions = f.read().splitlines()
    f.close()

    i = 0
    for function in functions:
        occurence = idaapi.find_binary(start, end, hex(hash(function)), 16, idaapi.SEARCH_DOWN)
        if occurence == idc.BADADDR:
            continue

        address = ida_helper.decode_ea(idc.next_head(occurence)).ops[1].addr

        ida_name.set_name(address, function, ida_name.SN_NOCHECK | ida_name.SN_FORCE)
        print(function + " found and renamed")
        i += 1

    print(str(i) + "/1337 lua functions resolved")

    

ida_helper.clear_window("Output window")

# elf_print_dvars(0xA6290)
# cod17_rename_dvars(0xE4098F0, 0x1AAA7000, "C:\\Users\\lgaducew\\Documents\\Visual Studio 2019\\Projects\\dreamware\\ida\\bo4_exported_dvar_names.txt")

# elf_print_lua_functions(0x10EF3A0)
# cod17_rename_lua_functions(0x1D44D20, 0x1D56267, "C:\\Users\\lgaducew\\Documents\\Visual Studio 2019\\Projects\\dreamware\\ida\\bo4_exported_lua_functions.txt")

print(hex(hash("GetPlayerName")))

# elf_print_lua_functions(0x91FA00)

# cod17_print_ecx(0x9F04710)
