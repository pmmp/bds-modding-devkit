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
    #Only export C++ mangled symbols - this is to avoid symbol conflicts with the likes of OpenSSL
    #They seem to compile OpenSSL statically, but dynamically link to system cURL which may use
    #a different, incompatible OpenSSL, resulting in wrong symbol resolving and crashes
    #this is the easiest workaround for now, but it might be a problem again in the future, or
    #if we need to access any non-mangled symbols from Minecraft (which aren't namespaced, so we
    #can't easily distinguish them from other libraries...)
    if not s.imported and (s.is_function or s.is_variable) and s.name.startswith('_Z'):
        s.visibility = lief.ELF.Symbol.VISIBILITY.DEFAULT
        if s.binding == lief.ELF.Symbol.BINDING.LOCAL:
            s.binding = lief.ELF.Symbol.BINDING.GLOBAL
        lib_symbols.add_dynamic_symbol(s)
lib_symbols.write(sys.argv[2])
