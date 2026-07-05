#!/system/bin/sh
# Copyright (C) 2026  TheGeniusClub
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, see <https://www.gnu.org/licenses/>.

MODDIR=${0%/*}

cd $MODDIR

sed -i 's/^description=.*/description=ForgeStore KeyMint attestation hook/' "$MODDIR/module.prop"

while true; do
    ./daemon "$MODDIR" || exit 1
    sleep 3
done &
