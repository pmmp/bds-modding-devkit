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
  ${LR}install${LC} ${W}         — ${LC}downloads the necessary files for server/mods
  ${LR}gen   ${LC}<${LY}name${LC}>     ${W}— ${LC}generates template for mod
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

case $1 in
	"install")
		printf "${LY} > Do you really want to download the server to this directory (Y/n)?$R "
		read answer
		if [[ "$answer" != "${answer#[Yy]}" ]]; then
			download $(curl -sL https://minecraft.net/en-us/download/server/bedrock/ | grep -Eo "https://\S*/bin-linux/\S*" | sed -e 's/^"//' -e 's/"$//') server.zip true
			echo "${LG} > Server was downloaded!$R"

			download $(get_latest_release "minecraft-linux/server-modloader" "*lib.*\.so") libserver_modloader.so
			mkdir -p mods/
			download $(get_latest_release "minecraft-linux/server-modloader-coremod" "*lib.*\.so") mods/libCoreMod.so

			echo "#!/bin/bash
PRELOAD=libserver_modloader.so
LIBS=.
BDS=./bedrock_server

start_server(){
	if [ -n \"\$VANILLA\" ]; then
		LD_LIBRARY_PATH=\$LIBS \$BDS \$@
	elif [ -n \"\$DEBUG\" ]; then
		gdb \$BDS \$@ -ex \"set environment LD_PRELOAD \$PRELOAD\" \\
			-ex \"set environment LD_LIBRARY_PATH \$LIBS\" \\
			-ex \"run\" \\
			-ex \"set confirm off\" \\
			-ex quit
	else
		LD_PRELOAD=\$PRELOAD LD_LIBRARY_PATH=\$LIBS ./bedrock_server \$@
	fi
}

while getopts \"vdl\" OPTION 2> /dev/null; do
	case \${OPTION} in
		v)
			VANILLA=true
			;;
		d)
			DEBUG=true
			;;
		l)
			DO_LOOP=true
			;;
		\?)
			break
			;;
	esac
done

if [ -n \"\$DO_LOOP\" ]; then
	while true; do
		start_server
		echo \"To escape the loop, press CTRL+C now. Otherwise, wait 5 seconds for the server to restart.\"
		echo \"\"
		sleep 5
	done
else
	start_server
fi
" > start.sh
			chmod +x start.sh

			setup_sdk
			echo "${LG} > modloader-sdk and CoreMod was downloaded!$R"
			echo "${LY} > modloader-sdk saved in $PWD$R"

			echo "${LY}>>> Installation successful. Try ${LG}./start.sh ${LY}<<<$R"
		fi
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
		;;
	*)
		show_help
		;;
esac
