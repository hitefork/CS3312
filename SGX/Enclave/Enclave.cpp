/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>

#include <stdlib.h>
#include <unistd.h>

#define STUDENT_ID_key "key522031910439"
#define MAX_BUFFER_SIZE 1024

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

// RC4 Implementation
struct rc4_state {
    unsigned char S[256];
    int i, j;
};

static struct rc4_state state;

// KSA
void rc4_init(const unsigned char *key, size_t len) {
    int i, j;
    unsigned char t;

    for (i = 0; i < 256; i++) {
        state.S[i] = (unsigned char)i;
    }

    for (i = 0, j = 0; i < 256; i++) {
        j = (j + state.S[i] + key[i % len]) % 256;
        t = state.S[i];
        state.S[i] = state.S[j];
        state.S[j] = t;
    }

    state.i = 0;
    state.j = 0;
}

// PRGA
void rc4_crypt(unsigned char *data, size_t len) {
    int i = state.i, j = state.j;
    unsigned char t;

    for (size_t k = 0; k < len; k++) {
        i = (i + 1) % 256;
        j = (j + state.S[i]) % 256;
        t = state.S[i];
        state.S[i] = state.S[j];
        state.S[j] = t;
        data[k] ^= state.S[(state.S[i] + state.S[j]) % 256];
    }

    state.i = i;
    state.j = j;
}

// 将十六进制字符转换为对应的数值 (0-15)
static int hex_char_to_int(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return 0; // 无效字符，返回0
}

// 将十六进制字符串转换为二进制数据
static int hex_string_to_binary(const char *hex_str, unsigned char *binary, size_t max_len) {
    size_t hex_len = strlen(hex_str);
    size_t bin_len = hex_len / 2; // 每两个十六进制字符对应一个字节
    
    if (bin_len > max_len) {
        return -1; // 二进制数据会超出缓冲区大小
    }
    
    for (size_t i = 0; i < bin_len; i++) {
        // 每两个十六进制字符转换为一个字节
        binary[i] = (hex_char_to_int(hex_str[i*2]) << 4) | hex_char_to_int(hex_str[i*2 + 1]);
    }
    
    return bin_len; // 返回转换后的二进制数据长度
}

// Main decryption workflow
void ecall_key_enclave() {
    unsigned char ciphertext[MAX_BUFFER_SIZE];
    int ciphertext_len = 0;

    // 1. Connect to server
    ocall_connect_to_server();

    // 2. Get ciphertext (as hex string)
    if (ocall_get_ciphertext(ciphertext, MAX_BUFFER_SIZE, &ciphertext_len) != 0) {
        printf("Critical: Failed to get ciphertext\n");
        ocall_disconnect_from_server();
        return;
    }

    printf("Received ciphertext (%d bytes)\n", ciphertext_len);

    // 输出原始接收到的十六进制密文
    printf("Hex Ciphertext: %s\n", ciphertext);

    // 3. Convert hex string to binary data
    unsigned char binary_ciphertext[MAX_BUFFER_SIZE/2]; // 十六进制字符串转二进制后长度减半
    int binary_len = hex_string_to_binary((const char *)ciphertext, binary_ciphertext, sizeof(binary_ciphertext));
    
    if (binary_len <= 0) {
        printf("Error: Invalid hex string or buffer too small\n");
        ocall_disconnect_from_server();
        return;
    }
    
    printf("Converted to binary (%d bytes)\n", binary_len);

    // 4. Prepare decryption
    const char *key = STUDENT_ID_key;
    int key_len = strlen(key);
    
    // 5. Perform RC4 decryption
    rc4_init((const unsigned char *)key, key_len);
    
    unsigned char *temp_buffer = (unsigned char *)malloc(binary_len + 1); // +1 for null terminator
    if (!temp_buffer) {
        printf("Critical: Memory allocation failed\n");
        ocall_disconnect_from_server();
        return;
    }
    
    memcpy(temp_buffer, binary_ciphertext, binary_len);
    
    rc4_crypt(temp_buffer, binary_len);
    
    // Null-terminate the plaintext
    temp_buffer[binary_len] = '\0';

    // 6. Output decrypted result via Ocall
    printf("Decrypted Result: %s\n", temp_buffer);

    // 7. Cleanup
    free(temp_buffer);
    ocall_disconnect_from_server();
}

void ecall_hello_enclave()
{
    printf("Hello SGX!\n");
}


