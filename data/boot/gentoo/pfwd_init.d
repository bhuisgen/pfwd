#!/sbin/runscript

extra_started_commands="reload"

depend() {
    need net
}

start() {
		if [ "${STARTUP}" = "1" ]; then
			ebegin "Starting pfwd"
			start-stop-daemon --start --pidfile /var/run/pfwd/pfwd.pid \
				--exec /usr/sbin/pfwd -- -c /etc/pfwd.conf
			eend $? "Failed to start pfwd"
		fi
}

stop() {
        ebegin "Stopping pfwd"
        start-stop-daemon --stop --pidfile /var/run/pfwd/pfwd.pid
        eend $? "Failed to stop pfwd"
}

reload() {
        ebegin "Reloading pfwd"
        kill -HUP `cat /var/run/pfwd/pfwd.pid` &>/dev/null
        eend $? "Failed to reload pfwd"
}
