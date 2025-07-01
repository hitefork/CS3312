#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void ecall_key_enclave(void);
void ecall_hello_enclave(void);

sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL ocall_connect_to_server(void);
sgx_status_t SGX_CDECL ocall_get_ciphertext(unsigned char* buffer, int buffer_size, int* ciphertext_len);
sgx_status_t SGX_CDECL ocall_disconnect_from_server(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
