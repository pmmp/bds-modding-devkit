#!/bin/bash
R=$(echo -en '\033[0m')
LR=$(echo -en '\033[01;31m')
LG=$(echo -en '\033[01;32m')
LY=$(echo -en '\033[01;33m')
LC=$(echo -en '\033[01;36m')
W=$(echo -en '\033[01;37m')

LIBS="$PWD/mods"
MODS_CODE="$PWD/code"
SDK="$PWD/sdk"
CMAKE_FLAGS="-DCMAKE_BUILD_TYPE=Debug"

show_help(){
	echo "${LC}Usage: $LG$0 ${LR}command ${LC}<${LY}arguments${LC}>

${LG}Available commands:
  ${LR}clean-server${LC} ${W} — ${LC}removes the old server binaries, leaving configs and worlds intact
  ${LR}install-server${LC} ${W} — ${LC}installs server files from the given directory
  ${LR}install-modloader${LC} — installs latest ModLoader binaries and SDK
  ${LR}gen ${LC}<${LY}name${LC}> ${W}— ${LC}generates template for mod
  ${LR}build ${LC}<${LY}all${LC}|${LY}name${LC}> ${W}— ${LC}builds all mods or selected$R"
}

download(){
	curl --insecure --silent --show-error --location --globoff $1 > $2
	if [[ "$3" = true ]]; then
		unzip -qq $2 && rm $2
	fi
}

get_latest_release(){
  curl -s "https://api.github.com/repos/$1/releases/latest" | grep '"browser_download_url":.'$2 | sed -E 's/.*"([^"]+)".*/\1/'
}

check_args(){
	if [ "$1" -ne $2 ]; then
		show_help && exit 0
	fi
}

setup_sdk(){
	local working_directory="$1"
	cd "$working_directory"
	rm -rf sdk && mkdir -p sdk && cd sdk
	download $(get_latest_release "minecraft-linux/server-modloader" "*\.zip") mod_sdk.zip true
}

build_mod(){
	if [[ -d "$MODS_CODE/$1" ]]; then
		if [[ -f "$1/CMakeLists.txt" ]]; then
			cd $1
		else
			cd $MODS_CODE/$1
		fi

		mkdir -p build && cd build
		cmake $CMAKE_FLAGS .. && make -j2 || exit 1

		cp *.so $LIBS
	else
		echo "${LR} Could not find $1"
	fi
}

clean_old_server(){
	local working_directory="$1"
	cd "$working_directory"
	rm -rf structures behavior_packs resource_packs definitions || true
	rm bedrock_server bedrock_server_symbols.debug bedrock_server_symbols_test.debug || true
	echo "${LG} > Old server files removed from ${working_directory}$R"
}

export_server_symbols(){
	local input_path="$1"
	local output_path="$2"

	echo "${LY} > Copying server binary"
	cp "$input_path" "$output_path"

	echo "${LY} > Stripping DWARF if present"
	strip --strip-debug "$output_path"

	echo "${LY} > Converting symbols"
	python3 export-symbols.py "$output_path" "$output_path"
}

copy_server_files(){
	local working_directory="$2"
	local server_files="$1"

	echo "${LY} > Installing new server files from $server_files (this might take a few minutes)${R}"
	cp -r "$server_files/structures" "$working_directory"
	cp -r "$server_files/behavior_packs" "$working_directory"
	cp -r "$server_files/resource_packs" "$working_directory"
	cp -r "$server_files/definitions" "$working_directory"
	cp "$server_files/bedrock_server" "$working_directory"
	cp "$server_files/bedrock_server_symbols.debug" "$working_directory"

	if [ ! -f "$working_directory/server.properties" ]; then
		echo "${LY} > Creating server.properties$R"
		cp "$server_files/server.properties" "$working_directory"
	else
		echo "${LY} > server.properties already exists$R"
	fi

	echo "${LG} > New server files installed!"
}

install_server(){
	local server_files="$1"
	local working_directory="$2"

	clean_old_server "$working_directory"

	copy_server_files "$server_files" "$working_directory"

	export_server_symbols "$working_directory/bedrock_server_symbols.debug" "$working_directory/bedrock_server_symbols_test.debug"

	echo "${LG} > Installation successful."
	echo "${LG} > Don't forget to build mods before running the server: ${LY}$0 build all$R"
}

install_modloader(){
	local working_directory="$1"
	setup_sdk "$working_directory"
	mkdir -p "$working_directory/mods/"
	download $(get_latest_release "minecraft-linux/server-modloader-coremod" "*lib.*\.so") "$working_directory/mods/libCoreMod.so"
}


case $1 in
	"clean-server")
		clean_old_server "$PWD"
		;;
	"install-server")
		check_args $# 2

		install_server "$2" "$PWD"
		;;
	"export-server-symbols")
		export_server_symbols "$PWD/bedrock_server_symbols.debug" "$PWD/bedrock_server_symbols_test.debug"
		;;
	"install-modloader")
		install_modloader "$PWD"
		echo "${LG} > modloader-sdk and CoreMod downloaded!$R"
		echo "${LY} > modloader-sdk saved in $PWD$R"

		echo "${LY}>>> Installation successful. Try ${LG}./start.sh ${LY}<<<$R"
		;;
	"gen")
		check_args $# 2

		mkdir -p "$MODS_CODE/$2/src" && cd $MODS_CODE
		echo "cmake_minimum_required(VERSION 3.0)
project($2)

set(CMAKE_PREFIX_PATH ../../sdk)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(ModLoader REQUIRED)

add_library($2 SHARED src/main.cpp)
target_link_libraries($2 PUBLIC ModLoader)" > "$MODS_CODE/$2/CMakeLists.txt"
		echo "#include <modloader/log.h>
#include <modloader/statichook.h>

using namespace modloader;

#define TAG \"$2\"

extern \"C\" void modloader_on_server_start(void* serverInstance) {
	Log::verbose(TAG, \"Hello, world!\");
}" > "$MODS_CODE/$2/src/main.cpp"
		;;
	"build")
		check_args $# 2

		if [[ "$2" == "all" ]]; then
			export -f build_mod && export LIBS=$LIBS
			find "$MODS_CODE" -mindepth 1 -maxdepth 1 -type d -print0 | xargs -0 -n1 -P4 -I '@' bash -c 'build_mod @'
		else
			build_mod $2
		fi
		echo "${LG} > All mods built successfully. To start the server with mods loaded, run ${LY}./start.sh$R"
		;;
	*)
		show_help
		;;
esac
