/*
 * Copyright (c) 2025, Nemesis Anticheat. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 */

#ifndef SHARE_VM_NEMESIS_NEMESIS_HPP
#define SHARE_VM_NEMESIS_NEMESIS_HPP

class nemesis : AllStatic {
 public:
  static bool validateModule(const char* path);
  static void kill(const char* reason);
};

#endif