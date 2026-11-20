# Runs as root before tabs open on an Alpine store that needs OpenRC.
set -eu
apk_offline() {
    apk --no-network --repositories-file /dev/null "$@"
}

# Use a temporary world entry for the local files so future upgrades can resolve the
# dependencies by name. A retry can resume after either package transaction.
if ! apk_offline info -e openrc >/dev/null; then
    # Existing systems may have upgraded dependencies. Ask apk for only the missing ones.
    set --
    for file in /var/cache/appine/openrc/*.apk; do
        name=${file##*/}
        name=${name%-r*.apk}
        apk_offline info -e "${name%-*}" >/dev/null || set -- "$@" "$file"
    done
    apk_offline add --virtual .appine-openrc "$@"
fi
apk_offline add openrc
if apk_offline info -e .appine-openrc >/dev/null; then
    apk_offline del .appine-openrc
fi
