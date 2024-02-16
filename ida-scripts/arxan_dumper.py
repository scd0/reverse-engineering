import idc, ida_dbg, ida_nalt


end = idc.find_binary(0x1000, idc.SEARCH_DOWN, "8B 45 00 83 F8 FF 0F 85 ? ? ? ? E9 ? ? ? ?");
# end = idc.find_binary(0x1000, idc.SEARCH_DOWN, "8B 45 ? 83 F8 FF 0F 85 ? ? ? ? E9 ? ? ? ?");
idc.add_bpt(end + 12);
idc.set_bpt_cond(end + 12, "PauseProcess();Warning(\"Ready to dump with scylla or any other dumping software you may use!\");");
ida_dbg.load_debugger("win32", 0);
ida_dbg.start_process(ida_nalt.get_input_file_path(), "", "");
