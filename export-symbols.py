import lief

lib_symbols = lief.parse("bedrock_server_symbols.debug")
for s in filter(lambda e: e.exported, lib_symbols.static_symbols):
    lib_symbols.add_dynamic_symbol(s)
lib_symbols.write("bedrock_server_symbols_test.debug")
