#!/system/bin/sh
MODDIR=${0%/*}

cd $MODDIR

# suppress logd visibility after boot completes
{
    while ! getprop sys.boot_completed >/dev/null 2>&1; do sleep 2; done
    resetprop persist.logd.size ""
    resetprop persist.logd.size.crash ""
    resetprop persist.logd.size.system ""
    resetprop persist.logd.size.main ""
} &

while true; do
    ./daemon "$MODDIR" || exit 1
    sleep 3
done &
