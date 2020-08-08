#!/bin/sh
# FightCade2 launcher for Linux and OSX
# (c)2013-2017 Pau Oliva Fora (@pof)

find_python() {

	python -V 2>&1 |grep "^Python 2\." >/dev/null
	if [ $? -eq 0 ]; then
		PYTHON=python
	else
		python2 -V 2>&1 |grep "^Python 2\." >/dev/null
		if [ $? -eq 0 ]; then
			PYTHON=python2
		else
			python2.7 -V 2>&1 |grep "^Python 2\." >/dev/null
			if [ $? -eq 0 ]; then
				PYTHON=python2.7
			else
				python2.6 -V 2>&1 |grep "^Python 2\." >/dev/null
				if [ $? -eq 0 ]; then
					PYTHON=python2.6
				fi
			fi
		fi
	fi
	if [ -z "${PYTHON}" ]; then
		echo "ERROR: can't find python 2.x"
		exit 1
	fi
}

# keep OSX happy:
cd "${0%/*}"

#kill previous instances
lsof -tn -iUDP:7001 |xargs -n 1 kill -9

find_python

PARAM=${1+"$@"}

THIS_SCRIPT_PATH=`readlink -f $0 2>/dev/null || pwd`
THIS_SCRIPT_DIR=`dirname ${THIS_SCRIPT_PATH}`

FPY="./fcade.py"
if [ ! -e ${FPY} ] ; then
	FPY="${THIS_SCRIPT_DIR}/fcade.py"
fi
if [ ! -e ${FPY} ] ; then
	echo "Can't find fcade.py"
	exit 1
fi

# rotate logs
if [ -f fcade.log.2 ]; then mv fcade.log.2 fcade.log.3 ; fi
if [ -f fcade.log.1 ]; then mv fcade.log.1 fcade.log.2 ; fi
if [ -f fcade.log ]; then mv fcade.log fcade.log.1 ; fi

if [ -x /usr/bin/xdg-mime ]; then
	# register fcade:// url handler
	mkdir -p ~/.local/share/applications/
	echo "[Desktop Entry]
Type=Application
Encoding=UTF-8
Name=FightCade Replay
Exec=${THIS_SCRIPT_DIR}/fcade.sh %U
Terminal=false
NoDisplay=true
StartupNotify=false
MimeType=x-scheme-handler/fcade
" > ~/.local/share/applications/fcade-quark.desktop
	xdg-mime default fcade-quark.desktop x-scheme-handler/fcade
fi
if [ -x /usr/bin/gconftool-2 ]; then
	gconftool-2 -t string -s /desktop/gnome/url-handlers/fcade/command "${THIS_SCRIPT_DIR}/fcade.sh %s"
	gconftool-2 -s /desktop/gnome/url-handlers/fcade/needs_terminal false -t bool
	gconftool-2 -t bool -s /desktop/gnome/url-handlers/fcade/enabled true
fi

#start the python wrapper
${PYTHON} ${FPY} ${PARAM} &
