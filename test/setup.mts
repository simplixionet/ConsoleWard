// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

import { register } from 'node:module'
import { pathToFileURL } from 'node:url'
register('./ts-resolver.mts', pathToFileURL('./test/'))
