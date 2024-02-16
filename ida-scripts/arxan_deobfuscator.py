# IDA - The Interactive Disassembler Version 7.7.220118 Windows x64 (64-bit address size)
# Python 3.10.7 (tags/v3.10.7:6cc6b13, Sep  5 2022, 14:08:36) [MSC v.1933 64 bit (AMD64)] on win32

import idc, ida_bytes
import ida_helper

def deobfuscate_segment(start, end):
    call = start - 5
    i = 0

    while True:
        call = idc.find_binary(call + 5, idc.SEARCH_DOWN, "e8 ? ff ff ff")
        if call == idc.BADADDR or call >= end:
            break

        jmp = ida_helper.decode_ea(call).ops[0].addr
        if ida_bytes.get_db_byte(jmp) != 0xeb:
            continue

        pop = ida_helper.decode_ea(ida_helper.decode_ea(jmp).ops[0].addr)
        if pop.get_canon_mnem() != "pop":
            continue
        idc.create_insn(pop.ea + 1)
        size = idc.get_item_size(pop.ea + 1)

        """ bottom = ida_bytes.get_db_byte(pop.ea)
        top = bottom - 0x58 + 0x50
        push = hex(top)[2:]
        bottom = idc.find_binary(pop.ea + 1 + size, idc.SEARCH_DOWN, hex(bottom)[2:])
        signature = push + " 9c"
        if ida_bytes.get_db_byte(bottom + 1) == 0x9d:
            bottom += 1
            signature = "9c " + push
        top = idc.find_binary(jmp, idc.SEARCH_UP, signature) """

        bottom = ida_bytes.get_db_byte(pop.ea)
        top = bottom - 0x58 + 0x50
        push = hex(top)[2:]
        bottom = idc.find_binary(pop.ea + 1 + size, idc.SEARCH_DOWN, hex(bottom)[2:])
        signature = push + " 9c"

        idc.create_insn(bottom + 1)
        size = idc.get_item_size(bottom + 1)

        if ida_bytes.get_db_byte(bottom + 1) == 0x9d:
            bottom += 1
            signature = "9c " + push
        if ida_bytes.get_db_byte(bottom + 1 + size) == 0x9d:
            bottom += 1 + size
            signature = "9c " + push
        top = idc.find_binary(jmp, idc.SEARCH_UP, signature)

        size = bottom - top + 1
        ar = b"\x90" * size 
        ida_bytes.patch_bytes(top, ar)
        print(hex(call) + " / " + hex(top) + " / " + hex(bottom))
        
        i += 1

    print(i)

ida_helper.clear_window("Output window")

""" Name	Start	End	R	W	X	D	L	Align	Base	Type	Class	AD	es	ss	ds	fs	gs
.text	0000000000001000	0000000006F03000	R	.	X	.	L	para	0001	public	CODE	64	0000	0000	0003	FFFFFFFFFFFFFFFF	FFFFFFFFFFFFFFFF
.rdata	0000000006F03000	0000000007422000	R	.	.	.	L	para	0002	public	DATA	64	0000	0000	0003	FFFFFFFFFFFFFFFF	FFFFFFFFFFFFFFFF
.data	0000000007422000	0000000019773000	R	W	.	.	L	para	0003	public	DATA	64	0000	0000	0003	FFFFFFFFFFFFFFFF	FFFFFFFFFFFFFFFF
.pdata	0000000019773000	00000000198E8000	R	.	.	.	L	para	0004	public	DATA	64	0000	0000	0003	FFFFFFFFFFFFFFFF	FFFFFFFFFFFFFFFF
_RDATA	00000000198E8000	00000000198FF000	R	.	.	.	L	para	0005	public	DATA	64	0000	0000	0003	FFFFFFFFFFFFFFFF	FFFFFFFFFFFFFFFF
.idata	0000000019AB4000	0000000019ABB000	R	W	.	.	L	para	0008	public	DATA	64	0000	0000	0003	FFFFFFFFFFFFFFFF	FFFFFFFFFFFFFFFF
.text	0000000019ABB000	0000000021432000	R	.	X	.	L	para	0007	public	CODE	64	0000	0000	0003	FFFFFFFFFFFFFFFF	FFFFFFFFFFFFFFFF """

# .text	0000000000001000	0000000006EF5000	R	.	X	.	L	para	0001	public	CODE	64	0000	0000	0003	FFFFFFFFFFFFFFFF	FFFFFFFFFFFFFFFF
deobfuscate_segment(0x1000, 0x6EF5000)

