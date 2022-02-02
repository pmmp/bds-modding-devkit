import lief

lib_symbols = lief.parse("bedrock_server_symbols.debug")
for s in lib_symbols.exported_symbols:
#    print(s)
    lib_symbols.add_dynamic_symbol(s)
lib_symbols.write("bedrock_server_symbols_test.debug")
