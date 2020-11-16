/*
This is the Prototype of bruteforce-fuzztesting automation code.
Designed in consideration of medcored project's all constraints.
*/
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "kafl_user.h"

#define CODE_MAX_LEN __LEN__

typedef enum {false, true} bool;

typedef struct _kAFL_IRP {
    uint32_t ioctlCode;
    int32_t inputBufferMin;
    int32_t inputBufferMax;
    int32_t outputBufferSize;
} kAFL_IRP;

kAFL_IRP constraints[] = {
__CONSTRAINTS__
};

bool filter_payload(uint8_t* data, int32_t size, kAFL_IRP *decoded_buf) 
{
    uint8_t codeIndex = data[0];
    if (codeIndex >= CODE_MAX_LEN)
        return false;
    decoded_buf->ioctlCode = constraints[codeIndex].ioctlCode;

    if (size < constraints[codeIndex].inputBufferMin + 1 || size > constraints[codeIndex].inputBufferMax + 1)
        return false;

    decoded_buf->outputBufferSize = constraints[codeIndex].outputBufferSize;
    
		return true;
}

int main(int argc, char** argv)
{
    kAFL_IRP decoded_buf;
    uint8_t outBuffer[0xffff];
    uint8_t buf[0xffff];
    kAFL_payload* payload_buffer = (kAFL_payload*)VirtualAlloc(0, PAYLOAD_SIZE, MEM_COMMIT, PAGE_READWRITE);
    memset(payload_buffer, 0xffff, PAYLOAD_SIZE);

    /* open vulnerable driver */
    HANDLE kafl_vuln_handle = NULL;
    kafl_vuln_handle = CreateFile((LPCSTR)"\\\\.\\__DEVICELINK__",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
        NULL
    );

    if (kafl_vuln_handle == INVALID_HANDLE_VALUE) {
        hprintf("[-] Cannot get device handle: 0x%X\n", GetLastError());
        ExitProcess(0); 
    }

    /* this hypercall submits the current CR3 value */ 
    kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (UINT64)payload_buffer);

    /* submit the guest virtual address of the payload buffer */
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);

    while (1) {
        /* request new payload (blocking) */
        kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);

        bool filter_res = filter_payload(payload_buffer->data, payload_buffer->size, &decoded_buf);
        if (filter_res == false)
            continue;

        memset(buf, 0x00, sizeof(buf));
        memcpy(buf, (const char *)&payload_buffer->data[1], payload_buffer->size - 1);
        for (int j = 0; j < payload_buffer->size - 1; j++) {
            if (buf[j] <= 0x20 || 0x7f <= buf[j]) {
                buf[j] = '.';
            }
        }
        hprintf("Injecting data... (code: 0x%x, payload: %s, size: %d)\n", decoded_buf.ioctlCode, buf, payload_buffer->size - 1);
        kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
        
        /* kernel fuzzing */
        DeviceIoControl(kafl_vuln_handle,
            decoded_buf.ioctlCode,
            (LPVOID)&payload_buffer->data[1],
            (DWORD)payload_buffer->size - 1,
            (LPVOID)outBuffer,
            (DWORD)decoded_buf.outputBufferSize,
            NULL,
            NULL
        );

        /* inform fuzzer about finished fuzzing iteration */
        hprintf("Injection finished.\n");
        kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
    }

    return 0;
}