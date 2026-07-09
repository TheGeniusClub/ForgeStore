/*
 * This file is part of ForgeStore
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program;
 * if not, see <https://www.gnu.org/licenses/>.
 *
 * Copyright (C) 2026 TheGeniusClub
 */

#include "hook.h"
#include "log.h"
#include <stdbool.h>

__attribute__((visibility("default"))) bool fm_entry(void *handle)
{
    (void)handle;

    if (fm_hook_init() < 0) {
        LOG("hook init failed");
        return false;
    }

    LOG("hooks installed");
    return true;
}
