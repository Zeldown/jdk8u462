/*
 * Copyright (c) 1999, 2014, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>

#include "jni.h"
#include "jni_util.h"
#include "jvm.h"

#include "java_util_UUID.h"

#ifdef _WIN32
    #include <windows.h>
    #include <shlobj.h>
    #include <direct.h>
    #define PATH_SEPARATOR "\\"
    #define mkdir(path, mode) _mkdir(path)
#else
    #include <unistd.h>
    #include <sys/stat.h>
    #include <pwd.h>
    #define PATH_SEPARATOR "/"
    #ifdef __APPLE__
        #include <mach/mach_time.h>
    #endif
#endif

#include <stdint.h>  /* for uintptr_t */

#define MAX_PATH_LEN 512
#define MAX_HWID_LEN 128
#define UUID_STRING_LEN 36
#define SALT "uqZyZAhof3Kp"
#define MAX_CACHE_LOCATIONS 1

#ifdef _WIN32
    static const char* CACHE_LOCATIONS[] = {"C:\\ProgramData\\01K0GPRWF8NAFGZFMYSWT9K0JY.dat"};
#elif defined(__APPLE__)
    static const char* CACHE_LOCATIONS[] = {"/Users/Shared/01K0GPRWF8NAFGZFMYSWT9K0JY.dat"};
#else
    static const char* CACHE_LOCATIONS[] = {"/var/tmp/01K0GPRWF8NAFGZFMYSWT9K0JY.dat"};
#endif

static void hashString(const char* input, const char* salt, char* output) {
    int i, j;
    int saltLen = (int)strlen(salt);
    int inputLen = (int)strlen(input);
    
    for (i = 0; i < inputLen; i++) {
        output[i] = input[i] ^ salt[i % saltLen] ^ (i + 1);
    }
    output[inputLen] = '\0';
}

static void unhashString(const char* hashed, const char* salt, char* output) {
    int i, j;
    int saltLen = (int)strlen(salt);
    int hashedLen = (int)strlen(hashed);
    
    for (i = 0; i < hashedLen; i++) {
        output[i] = hashed[i] ^ salt[i % saltLen] ^ (i + 1);
    }
    output[hashedLen] = '\0';
}

static void toHex(const char* input, char* output) {
    const char* hex_chars = "0123456789abcdef";
    int len = (int)strlen(input);
    int i;
    
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)input[i];
        output[i * 2] = hex_chars[c >> 4];
        output[i * 2 + 1] = hex_chars[c & 0x0F];
    }
    output[len * 2] = '\0';
}

static void fromHex(const char* hex_input, char* output) {
    int hex_len = (int)strlen(hex_input);
    int i;
    
    for (i = 0; i < hex_len; i += 2) {
        char hex_byte[3];
        hex_byte[0] = hex_input[i];
        hex_byte[1] = hex_input[i + 1];
        hex_byte[2] = '\0';
        output[i / 2] = (char)strtol(hex_byte, NULL, 16);
    }
    output[hex_len / 2] = '\0';
}

static unsigned int mix_entropy(unsigned int entropy) {
    entropy ^= entropy << 13;
    entropy ^= entropy >> 17;
    entropy ^= entropy << 5;
    return entropy;
}

static void generateCustomUUID(char* uuid_str) {
    const char* hex_chars = "0123456789abcdef";
    int i;
    unsigned int entropy[5] = {0};
    
    entropy[0] = (unsigned int)time(NULL);
    entropy[1] = (unsigned int)clock();
#ifdef _WIN32
    entropy[2] = (unsigned int)GetCurrentProcessId();
    entropy[3] = (unsigned int)GetTickCount();
#else
    entropy[2] = (unsigned int)getpid();
#ifdef __APPLE__
    entropy[3] = (unsigned int)mach_absolute_time();
#else
    entropy[3] = (unsigned int)rand();
#endif
#endif
    entropy[4] = (unsigned int)(uintptr_t)&entropy;
    
    for (i = 0; i < 5; i++) {
        entropy[0] = mix_entropy(entropy[0] ^ entropy[i]);
    }
    
    srand(entropy[0]);
    
    uuid_str[0] = 'd';
    
    for (i = 1; i < UUID_STRING_LEN; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            uuid_str[i] = '-';
        } else if (i == UUID_STRING_LEN - 1) {
            uuid_str[i] = '3';
        } else {
            unsigned int r = (rand() ^ mix_entropy((unsigned int)i * entropy[i % 5])) % 16;
            uuid_str[i] = hex_chars[r];
        }
    }
    
    uuid_str[UUID_STRING_LEN] = '\0';
}

static int createDirectory(const char* path) {
    char temp_path[MAX_PATH_LEN];
    char* p = NULL;
    size_t len;
    int result;
    
    strncpy(temp_path, path, sizeof(temp_path) - 1);
    temp_path[sizeof(temp_path) - 1] = '\0';
    len = strlen(temp_path);
    
    if (temp_path[len - 1] == PATH_SEPARATOR[0])
        temp_path[len - 1] = '\0';
    
    for (p = temp_path + 1; *p; p++) {
        if (*p == PATH_SEPARATOR[0]) {
            *p = '\0';
#ifdef _WIN32
            result = _mkdir(temp_path);
#else
            result = mkdir(temp_path, 0755);
#endif
            *p = PATH_SEPARATOR[0];
        }
    }
    
#ifdef _WIN32
    result = _mkdir(temp_path);
    return result;
#else
    result = mkdir(temp_path, 0755);
    return result;
#endif
}

static void getCacheFilePath(char* full_path, int location_index) {
    if (location_index >= 0 && location_index < MAX_CACHE_LOCATIONS) {
        strncpy(full_path, CACHE_LOCATIONS[location_index], MAX_PATH_LEN - 1);
        full_path[MAX_PATH_LEN - 1] = '\0';
    } else {
        full_path[0] = '\0';
    }
}

static int readHwidFromCache(char* hwid) {
    char cache_path[MAX_PATH_LEN];
    char hex_content[MAX_HWID_LEN * 2 + 1];
    char hashed_content[MAX_HWID_LEN];
    FILE* file;
    int i;
    
    for (i = 0; i < MAX_CACHE_LOCATIONS; i++) {
        getCacheFilePath(cache_path, i);
        
        file = fopen(cache_path, "rb");
        if (file) {
            if (fgets(hex_content, sizeof(hex_content), file) != NULL) {
                size_t len = strlen(hex_content);
                
                if (len > 0 && hex_content[len-1] == '\n') {
                    hex_content[len-1] = '\0';
                }
                
                fromHex(hex_content, hashed_content);
                unhashString(hashed_content, SALT, hwid);
                fclose(file);
                
                if (strlen(hwid) == UUID_STRING_LEN && hwid[0] == 'd' && hwid[UUID_STRING_LEN-1] == '3') {
                    return 1;
                }
            }
            fclose(file);
        }
    }
    
    return 0;
}

static void writeHwidToCache(const char* hwid) {
    char cache_path[MAX_PATH_LEN];
    char dir_path[MAX_PATH_LEN];
    char hashed_content[MAX_HWID_LEN];
    char hex_content[MAX_HWID_LEN * 2 + 1];
    char* last_sep;
    FILE* file;
    int i;
    int success = 0;
    
    hashString(hwid, SALT, hashed_content);
    toHex(hashed_content, hex_content);
    
    for (i = 0; i < MAX_CACHE_LOCATIONS; i++) {
        getCacheFilePath(cache_path, i);
        
        strncpy(dir_path, cache_path, sizeof(dir_path) - 1);
        dir_path[sizeof(dir_path) - 1] = '\0';
        last_sep = strrchr(dir_path, PATH_SEPARATOR[0]);
        if (last_sep) {
            *last_sep = '\0';
            createDirectory(dir_path);
        }
        
#ifdef _WIN32
        DWORD existing_attrs = GetFileAttributesA(cache_path);
        if (existing_attrs != INVALID_FILE_ATTRIBUTES) {
            if (existing_attrs & (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_SYSTEM)) {
                DWORD new_attrs = existing_attrs & ~(FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_SYSTEM);
                SetFileAttributesA(cache_path, new_attrs);
            }
        }
#endif
        
        file = fopen(cache_path, "wb");
        if (!file) {
#ifdef _WIN32
            if (existing_attrs != INVALID_FILE_ATTRIBUTES) {
                SetFileAttributesA(cache_path, FILE_ATTRIBUTE_NORMAL);
                if (DeleteFileA(cache_path)) {
                    file = fopen(cache_path, "wb");
                }
            }
#endif
        }
        
        if (file) {
            fprintf(file, "%s\n", hex_content);
            fclose(file);
            
#ifdef _WIN32
            SetFileAttributesA(cache_path, FILE_ATTRIBUTE_HIDDEN);
#else
            chmod(cache_path, 0600);
#endif
            success = 1;
            break;
        }
    }
    
    if (!success) {
        fprintf(stderr, "FATAL ERROR: Unable to create cache file. JVM will terminate.\n");
        exit(1);
    }
}

JNIEXPORT jstring JNICALL
Java_java_util_UUID_getRandomUUID(JNIEnv *env, jclass ign)
{
    char hwid[MAX_HWID_LEN];
    
    if (readHwidFromCache(hwid) && strlen(hwid) == UUID_STRING_LEN) {
        return JNU_NewStringPlatform(env, hwid);
    } else {
        generateCustomUUID(hwid);
        writeHwidToCache(hwid);
        return JNU_NewStringPlatform(env, hwid);
    }
}
