#!/bin/sh
if [ "$#" -eq 0 ]; then
    echo 'Usage: appine-gpu COMMAND [ARG...]' >&2
    exit 2
fi

icd_dir=/usr/share/vulkan/icd.d
for manifest in "$icd_dir/virtio_icd.aarch64.json" "$icd_dir/virtio_icd.json"; do
    if [ -r "$manifest" ]; then
        export VK_DRIVER_FILES="$manifest"
        exec "$@"
    fi
done

echo 'appine-gpu: Mesa Venus driver missing. Install mesa-vulkan-virtio on Alpine or mesa-vulkan-drivers on Debian.' >&2
exit 1
