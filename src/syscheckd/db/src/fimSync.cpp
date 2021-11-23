/*
 * Wazuh SysCollector
 * Copyright (C) 2015-2021, Wazuh Inc.
 * November 23, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "fimSync.hpp"

#ifdef WIN32
DWORD WINAPI fim_run_integrity(void __attribute__((unused)) * args) {
#else
void * fim_run_integrity(void * args) {
#endif

    std::mutex sync_mutex;
    std::unique_lock<std::mutex> lock{sync_mutex};

    registerRsync();
    loopRsync(lock);

#ifndef WIN32
    return args;
#endif
}
