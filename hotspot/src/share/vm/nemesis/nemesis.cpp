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

#include "precompiled.hpp"
#include "nemesis/nemesis.hpp"
#include "runtime/os.hpp"
#include "utilities/ostream.hpp"

#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <cstring>
#include <cstdlib>
#include <stdio.h>
#include <time.h>
#include <cctype>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

static const char* stristr(const char* haystack, const char* needle) {
  if (!haystack || !needle) return NULL;
  
  size_t needle_len = strlen(needle);
  size_t haystack_len = strlen(haystack);
  
  if (needle_len > haystack_len) return NULL;
  
  for (size_t i = 0; i <= haystack_len - needle_len; i++) {
    bool match = true;
    for (size_t j = 0; j < needle_len; j++) {
      if (tolower(haystack[i + j]) != tolower(needle[j])) {
        match = false;
        break;
      }
    }
    if (match) {
      return &haystack[i];
    }
  }
  return NULL;
}

bool nemesis::validateModule(const char* path) {
  if (path == NULL) {
    return false;
  }

  if (stristr(path, ".paladium") != NULL && (stristr(path, "java/bin") != NULL || stristr(path, "java/jre/bin") != NULL || stristr(path, "java/lib") != NULL || stristr(path, "natives/1.7.10") != NULL || stristr(path, "java\\bin") != NULL || stristr(path, "java\\jre\\bin") != NULL || stristr(path, "java\\lib") != NULL ||  stristr(path, "natives\\1.7.10") != NULL)) {
    return true;
  }

  if ((stristr(path, "/temp/jna-") != NULL || stristr(path, "\\temp\\jna-") != NULL) && (stristr(path, "\\jna") != NULL || stristr(path, "/jna") != NULL) && stristr(path, ".dll") != NULL) {
    return true;
  }

  if ((stristr(path, "\\system32\\") != NULL || stristr(path, "\\syswow64\\") != NULL || stristr(path, "/system32/") != NULL || stristr(path, "/syswow64/") != NULL) && stristr(path, ".dll") != NULL) {
    return true;
  }

  int len = MultiByteToWideChar(CP_UTF8, 0, path, -1, NULL, 0);
  if (len == 0) {
    return false;
  }
  
  wchar_t* wide_path = (wchar_t*)malloc(len * sizeof(wchar_t));
  if (wide_path == NULL) {
    return false;
  }
  
  MultiByteToWideChar(CP_UTF8, 0, path, -1, wide_path, len);

  WINTRUST_FILE_INFO file_info;
  memset(&file_info, 0, sizeof(file_info));
  file_info.cbStruct = sizeof(WINTRUST_FILE_INFO);
  file_info.pcwszFilePath = wide_path;
  file_info.hFile = NULL;
  file_info.pgKnownSubject = NULL;

  GUID policy_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
  WINTRUST_DATA trust_data;
  memset(&trust_data, 0, sizeof(trust_data));
  trust_data.cbStruct = sizeof(WINTRUST_DATA);
  trust_data.pPolicyCallbackData = NULL;
  trust_data.pSIPClientData = NULL;
  trust_data.dwUIChoice = WTD_UI_NONE;
  trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
  trust_data.dwUnionChoice = WTD_CHOICE_FILE;
  trust_data.dwStateAction = WTD_STATEACTION_VERIFY;
  trust_data.hWVTStateData = NULL;
  trust_data.pwszURLReference = NULL;
  trust_data.dwUIContext = 0;
  trust_data.pFile = &file_info;

  LONG result = WinVerifyTrust(NULL, &policy_guid, &trust_data);
  
  trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
  WinVerifyTrust(NULL, &policy_guid, &trust_data);
  free(wide_path);

  return (result == ERROR_SUCCESS);
}

void nemesis::kill(const char* reason) {
  const char* key = "gDjXkAP0Aw";
  size_t key_len = strlen(key);
  size_t reason_len = strlen(reason);
  
  char* encrypted = (char*)malloc(reason_len + 1);
  if (encrypted != NULL) {
    for (size_t i = 0; i < reason_len; i++) {
      encrypted[i] = reason[i] ^ key[i % key_len];
    }
    encrypted[reason_len] = '\0';
    
    srand((unsigned int)time(NULL));
    int filename_len = 5 + (rand() % 6);
    char* random_filename = (char*)malloc(filename_len + 1);
    
    if (random_filename != NULL) {
      const char* chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
      size_t chars_len = strlen(chars);
      
      for (int i = 0; i < filename_len; i++) {
        random_filename[i] = chars[rand() % chars_len];
      }
      random_filename[filename_len] = '\0';
      
      FILE* debug_file = fopen(random_filename, "wb");
      if (debug_file != NULL) {
        fwrite(encrypted, 1, reason_len, debug_file);
        fclose(debug_file);
      }
      
      free(random_filename);
    }
    
    free(encrypted);
  }
  
  os::die();
}