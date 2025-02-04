#!/bin/bash
PRELOAD=sdk/lib/libserver_modloader.so
LIBS=.
[ -z "$BDS" ] && BDS=./bedrock_server_symbols_test.debug

start_server(){
	if [ -n "$VANILLA" ]; then
		LD_LIBRARY_PATH=$LIBS $BDS $@
	elif [ -n "$DEBUG" ]; then
		#auto-load safe-path disabled to allow libthread_db to load
		gdb \
			-ex "set exec-wrapper env 'LD_PRELOAD=$PRELOAD'" \
			-ex "set auto-load safe-path /" \
			-ex "echo ----- Mod debugging set up. Type \"run\" to start the server. -----\n" \
			$BDS $@
	else
		LD_PRELOAD=$PRELOAD LD_LIBRARY_PATH=$LIBS $BDS $@
	fi
}

while getopts "vdl" OPTION 2> /dev/null; do
	case ${OPTION} in
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

if [ -n "$DO_LOOP" ]; then
	while true; do
		start_server
		echo "To escape the loop, press CTRL+C now. Otherwise, wait 5 seconds for the server to restart."
		echo ""
		sleep 5
	done
else
	start_server
fi

