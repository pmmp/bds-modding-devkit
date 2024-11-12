import lief
import sys

if len(sys.argv) < 3:
    print("Required arguments: input path, output path")
    exit(1)


lib_symbols = lief.parse(sys.argv[1])
if lib_symbols is None:
    print("Error opening given BDS file, aborting")
    exit(1)

for s in lib_symbols.symtab_symbols:
    #only modify local symbols to minimize scope
    s.visibility = lief.ELF.Symbol.VISIBILITY.DEFAULT
    if s.binding == lief.ELF.Symbol.BINDING.LOCAL:
        s.binding = lief.ELF.Symbol.BINDING.GLOBAL
    lib_symbols.add_dynamic_symbol(s)
lib_symbols.write(sys.argv[2])
