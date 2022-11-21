#!/bin/bash
R=$(echo -en '\033[0m')
LR=$(echo -en '\033[01;31m')
LG=$(echo -en '\033[01;32m')
LY=$(echo -en '\033[01;33m')
LC=$(echo -en '\033[01;36m')
W=$(echo -en '\033[01;37m')

show_help(){
	echo "${LC}Usage: $LG$0 ${LR}command ${LC}<${LY}arguments${LC}>

${LG}Available commands:
  ${LR}setup ${LC}<${LY}server files path${LC}>${W} — ${LC}sets everything up from scratch for the first time
  ${LR}clean-server${W} — ${LC}removes the old server binaries, leaving configs and worlds intact
  ${LR}install-server ${LC}<${LY}server files path${LC}>${W} — ${LC}installs server files from the given directory
  ${LR}install-modloader${W} — ${LC}installs latest ModLoader binaries and SDK
  ${LR}gen ${LC}<${LY}name${LC}>${W} — ${LC}generates template for mod
  ${LR}build ${LC}<${LY}all${LC}|${LY}name${LC}>${W} — ${LC}builds all mods or selected$R"
}

case $1 in
	"setup")
		./scripts/setup "$@"
		;;
	"clean-server")
		./scripts/clean-server "$@"
		;;
	"install-server")
		./scripts/install-server "$@"
		;;
	"export-server-symbols")
		./scripts/export-server-symbols "$@"
		;;
	"install-modloader")
		./scripts/install-modloader "$@"
		;;
	"gen")
		./scripts/gen "$@"
		;;
	"build")
		./scripts/build "$@"
		;;
	*)
		show_help
		;;
esac
