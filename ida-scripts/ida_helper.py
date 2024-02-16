# IDA - The Interactive Disassembler Version 7.7.220118 Windows x64 (64-bit address size)
# Python 3.10.7 (tags/v3.10.7:6cc6b13, Sep  5 2022, 14:08:36) [MSC v.1933 64 bit (AMD64)] on win32

import ida_kernwin, ida_ua

def clear_window(window):
    form = ida_kernwin.find_widget(window)
    ida_kernwin.activate_widget(form, True)
    ida_kernwin.process_ui_action("msglist:Clear")

def decode_ea(ea):
    insn = ida_ua.insn_t()
    ida_ua.decode_insn(insn, ea)
    return insn
