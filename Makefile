clean:
	rm -rf structures behavior_packs resource_packs definitions || true
	rm bedrock_server bedrock_server_symbols.debug bedrock_server_symbols_test.debug || true

rewrite-symbols:
	cp bedrock_server_symbols.debug bedrock_server_symbols_backup.debug
	strip --strip-debug bedrock_server_symbols.debug
	python3 export-symbols.py
	strip --strip-debug bedrock_server_symbols_test.debug
	chmod +x ./bedrock_server_symbols_test.debug
	cp bedrock_server_symbols_backup.debug bedrock_server_symbols.debug

copy-files: clean
	cp -r "$(server_files)/structures" .
	cp -r "$(server_files)/behavior_packs" .
	cp -r "$(server_files)/resource_packs" .
	cp -r "$(server_files)/definitions" .
	cp "$(server_files)/bedrock_server" .
	cp "$(server_files)/bedrock_server_symbols.debug" .

install: copy-files rewrite-symbols

mods:
	./helper.sh build all

run: mods
	./start.sh -d
