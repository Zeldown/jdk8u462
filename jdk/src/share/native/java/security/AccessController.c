#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#include <wincrypt.h>
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")
#endif

#include <stdio.h>
#include <stdint.h>

#include <string.h>

#include "jni.h"
#include "jvm.h"
#include "java_security_AccessController.h"

#include <jni.h>
#include <jvmti.h>

/*
 * Copyright (c) 1997, 1998, Oracle and/or its affiliates. All rights reserved.
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

static JNINativeMethod methods[] = {
    {"getLoadedDlls", "()Ljava/util/List;", (void*)Java_java_security_AccessController_getLoadedDlls},
    {"getLoadedClassesNative", "()Ljava/util/List;", (void*)Java_java_security_AccessController_getLoadedClassesNative},
};

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    JNIEnv* env;
    if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    jclass cls = (*env)->FindClass(env, "java/security/AccessController");
    if (cls == NULL) return JNI_ERR;
    if ((*env)->RegisterNatives(env, cls, methods, sizeof(methods)/sizeof(methods[0])) != 0) return JNI_ERR;
    return JNI_VERSION_1_6;
}

static jvmtiEnv* get_jvmti_env(JavaVM* jvm) {
    jvmtiEnv* jvmti = NULL;
    jint res = (*jvm)->GetEnv(jvm, (void**)&jvmti, JVMTI_VERSION_1_2);
    if (res != JNI_OK || jvmti == NULL) return NULL;
    return jvmti;
}

/*
 * Class:     java_security_AccessController
 * Method:    getLoadedClassesNative
 * Signature: ()Ljava/util/List;
 */
JNIEXPORT jobject JNICALL Java_java_security_AccessController_getLoadedClassesNative(JNIEnv *env, jclass cls) {
    JavaVM* jvm;
    (*env)->GetJavaVM(env, &jvm);
    jvmtiEnv* jvmti = get_jvmti_env(jvm);
    if (jvmti == NULL) return NULL;

    jint class_count = 0;
    jclass* classes = NULL;
    if ((*jvmti)->GetLoadedClasses(jvmti, &class_count, &classes) != JVMTI_ERROR_NONE) return NULL;

    jclass arrayListClass = (*env)->FindClass(env, "java/util/ArrayList");
    jmethodID arrayListInit = (*env)->GetMethodID(env, arrayListClass, "<init>", "()V");
    jmethodID arrayListAdd = (*env)->GetMethodID(env, arrayListClass, "add", "(Ljava/lang/Object;)Z");
    jobject arrayList = (*env)->NewObject(env, arrayListClass, arrayListInit);

    jclass loadedClassInfoClass = (*env)->FindClass(env, "java/security/AccessController$LoadedClassInfo");
    jmethodID loadedClassInfoCtor = (*env)->GetMethodID(env, loadedClassInfoClass, "<init>", "(Ljava/lang/String;)V");

    for (int i = 0; i < class_count; i++) {
        char* signature = NULL;
        if ((*jvmti)->GetClassSignature(jvmti, classes[i], &signature, NULL) != JVMTI_ERROR_NONE) continue;
        char className[512];
        if (signature[0] == 'L') {
            strncpy(className, signature + 1, sizeof(className));
            char* semi = strchr(className, ';');
            if (semi) *semi = '\0';
            for (char* p = className; *p; ++p) if (*p == '/') *p = '.';
        } else {
            strncpy(className, signature, sizeof(className));
        }
        jstring jName = (*env)->NewStringUTF(env, className);
        (*jvmti)->Deallocate(jvmti, (unsigned char*)signature);

        jobject classInfo = (*env)->NewObject(env, loadedClassInfoClass, loadedClassInfoCtor, jName);
        (*env)->CallBooleanMethod(env, arrayList, arrayListAdd, classInfo);
    }
    if (classes) (*jvmti)->Deallocate(jvmti, (unsigned char*)classes);
    return arrayList;
}

/*
 * Class:     java_security_AccessController
 * Method:    getLoadedDlls
 * Signature: ()Ljava/util/List;
 */
JNIEXPORT jobject JNICALL Java_java_security_AccessController_getLoadedDlls(JNIEnv *env, jclass cls) {
#ifdef _WIN32
    HMODULE hMods[1024];
    HANDLE hProcess;
    DWORD cbNeeded;
    int i;
    jobject arrayList = NULL;
    jclass arrayListClass = NULL;
    jmethodID arrayListInit = NULL;
    jmethodID arrayListAdd = NULL;
    jclass loadedDllInfoClass = NULL;
    jmethodID loadedDllInfoCtor = NULL;

    hProcess = GetCurrentProcess();
    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        return NULL;
    }
    int count = cbNeeded / sizeof(HMODULE);

    arrayListClass = (*env)->FindClass(env, "java/util/ArrayList");
    arrayListInit = (*env)->GetMethodID(env, arrayListClass, "<init>", "()V");
    arrayListAdd = (*env)->GetMethodID(env, arrayListClass, "add", "(Ljava/lang/Object;)Z");
    arrayList = (*env)->NewObject(env, arrayListClass, arrayListInit);

    loadedDllInfoClass = (*env)->FindClass(env, "java/security/AccessController$LoadedDllInfo");
    loadedDllInfoCtor = (*env)->GetMethodID(env, loadedDllInfoClass, "<init>", "(Ljava/lang/String;Ljava/lang/String;JJLjava/lang/String;)V");

    for (i = 0; i < count; i++) {
        TCHAR szModName[MAX_PATH];
        if (GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName)/sizeof(TCHAR))) {
            char *baseName = strrchr(szModName, '\\');
            baseName = baseName ? baseName + 1 : szModName;
            jstring jName = (*env)->NewStringUTF(env, baseName);
            jstring jPath = (*env)->NewStringUTF(env, szModName);

            HANDLE hFile = CreateFile(szModName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            long long size = 0;
            if (hFile != INVALID_HANDLE_VALUE) {
                LARGE_INTEGER li;
                if (GetFileSizeEx(hFile, &li)) {
                    size = li.QuadPart;
                }
            }

            FILETIME ftCreate, ftAccess, ftWrite;
            long long loadTime = 0;
            if (hFile != INVALID_HANDLE_VALUE && GetFileTime(hFile, &ftCreate, &ftAccess, &ftWrite)) {
                ULARGE_INTEGER ull;
                ull.LowPart = ftWrite.dwLowDateTime;
                ull.HighPart = ftWrite.dwHighDateTime;
                loadTime = ull.QuadPart;
            }

            char hashStr[65] = {0};
            if (hFile != INVALID_HANDLE_VALUE) {
                BYTE buffer[4096];
                DWORD bytesRead;
                HCRYPTPROV hProv = 0;
                HCRYPTHASH hHash = 0;
                if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
                    if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
                        SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
                        while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
                            CryptHashData(hHash, buffer, bytesRead, 0);
                        }
                        BYTE hash[32];
                        DWORD hashLen = 32;
                        if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
                            for (int k = 0; k < 32; k++) {
                                sprintf(hashStr + k*2, "%02x", hash[k]);
                            }
                        }
                        CryptDestroyHash(hHash);
                    }
                    CryptReleaseContext(hProv, 0);
                }
            }
            if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
            jstring jHash = (*env)->NewStringUTF(env, hashStr);

            jobject dllInfo = (*env)->NewObject(env, loadedDllInfoClass, loadedDllInfoCtor,
                jName, jPath, (jlong)size, (jlong)loadTime, jHash);
            (*env)->CallBooleanMethod(env, arrayList, arrayListAdd, dllInfo);
        }
    }
    return arrayList;
#else
    return NULL;
#endif
}

/*
 * Class:     java_security_AccessController
 * Method:    doPrivileged
 * Signature: (Ljava/security/PrivilegedAction;)Ljava/lang/Object;
 */
JNIEXPORT jobject JNICALL Java_java_security_AccessController_doPrivileged__Ljava_security_PrivilegedAction_2
  (JNIEnv *env, jclass cls, jobject action)
{
    return JVM_DoPrivileged(env, cls, action, NULL, JNI_FALSE);
}

/*
 * Class:     java_security_AccessController
 * Method:    doPrivileged
 * Signature: (Ljava/security/PrivilegedAction;Ljava/security/AccessControlContext;)Ljava/lang/Object;
 */
JNIEXPORT jobject JNICALL Java_java_security_AccessController_doPrivileged__Ljava_security_PrivilegedAction_2Ljava_security_AccessControlContext_2
  (JNIEnv *env, jclass cls, jobject action, jobject context)
{
    return JVM_DoPrivileged(env, cls, action, context, JNI_FALSE);
}

/*
 * Class:     java_security_AccessController
 * Method:    doPrivileged
 * Signature: (Ljava/security/PrivilegedExceptionAction;)Ljava/lang/Object;
 */
JNIEXPORT jobject JNICALL Java_java_security_AccessController_doPrivileged__Ljava_security_PrivilegedExceptionAction_2
  (JNIEnv *env, jclass cls, jobject action)
{
    return JVM_DoPrivileged(env, cls, action, NULL, JNI_TRUE);
}

/*
 * Class:     java_security_AccessController
 * Method:    doPrivileged
 * Signature: (Ljava/security/PrivilegedExceptionAction;Ljava/security/AccessControlContext;)Ljava/lang/Object;
 */
JNIEXPORT jobject JNICALL Java_java_security_AccessController_doPrivileged__Ljava_security_PrivilegedExceptionAction_2Ljava_security_AccessControlContext_2
  (JNIEnv *env, jclass cls, jobject action, jobject context)
{
    return JVM_DoPrivileged(env, cls, action, context, JNI_TRUE);
}

JNIEXPORT jobject JNICALL
Java_java_security_AccessController_getStackAccessControlContext(
                                                              JNIEnv *env,
                                                              jobject this)
{
    return JVM_GetStackAccessControlContext(env, this);
}


JNIEXPORT jobject JNICALL
Java_java_security_AccessController_getInheritedAccessControlContext(
                                                              JNIEnv *env,
                                                              jobject this)
{
    return JVM_GetInheritedAccessControlContext(env, this);
}
