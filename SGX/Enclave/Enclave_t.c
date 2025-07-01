#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_get_ciphertext_t {
	unsigned char* ms_buffer;
	int ms_buffer_size;
	int* ms_ciphertext_len;
} ms_ocall_get_ciphertext_t;

static sgx_status_t SGX_CDECL sgx_ecall_key_enclave(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_key_enclave();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_hello_enclave(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_hello_enclave();
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[2];
} g_ecall_table = {
	2,
	{
		{(void*)(uintptr_t)sgx_ecall_key_enclave, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_hello_enclave, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[4][2];
} g_dyn_entry_table = {
	4,
	{
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

	if (str != NULL) {
		if (memcpy_verw_s(&ms->ms_str, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}

	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_connect_to_server(void)
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(1, NULL);

	return status;
}
sgx_status_t SGX_CDECL ocall_get_ciphertext(unsigned char* buffer, int buffer_size, int* ciphertext_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buffer = buffer_size;
	size_t _len_ciphertext_len = sizeof(int);

	ms_ocall_get_ciphertext_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_get_ciphertext_t);
	void *__tmp = NULL;

	void *__tmp_buffer = NULL;
	void *__tmp_ciphertext_len = NULL;

	CHECK_ENCLAVE_POINTER(buffer, _len_buffer);
	CHECK_ENCLAVE_POINTER(ciphertext_len, _len_ciphertext_len);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buffer != NULL) ? _len_buffer : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (ciphertext_len != NULL) ? _len_ciphertext_len : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_get_ciphertext_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_get_ciphertext_t));
	ocalloc_size -= sizeof(ms_ocall_get_ciphertext_t);

	if (buffer != NULL) {
		if (memcpy_verw_s(&ms->ms_buffer, sizeof(unsigned char*), &__tmp, sizeof(unsigned char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_buffer = __tmp;
		if (_len_buffer % sizeof(*buffer) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_buffer, 0, _len_buffer);
		__tmp = (void *)((size_t)__tmp + _len_buffer);
		ocalloc_size -= _len_buffer;
	} else {
		ms->ms_buffer = NULL;
	}

	if (memcpy_verw_s(&ms->ms_buffer_size, sizeof(ms->ms_buffer_size), &buffer_size, sizeof(buffer_size))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (ciphertext_len != NULL) {
		if (memcpy_verw_s(&ms->ms_ciphertext_len, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_ciphertext_len = __tmp;
		if (_len_ciphertext_len % sizeof(*ciphertext_len) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_ciphertext_len, 0, _len_ciphertext_len);
		__tmp = (void *)((size_t)__tmp + _len_ciphertext_len);
		ocalloc_size -= _len_ciphertext_len;
	} else {
		ms->ms_ciphertext_len = NULL;
	}

	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (buffer) {
			if (memcpy_s((void*)buffer, _len_buffer, __tmp_buffer, _len_buffer)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (ciphertext_len) {
			if (memcpy_s((void*)ciphertext_len, _len_ciphertext_len, __tmp_ciphertext_len, _len_ciphertext_len)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_disconnect_from_server(void)
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(3, NULL);

	return status;
}
