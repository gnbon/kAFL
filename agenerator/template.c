/*
This is the Prototype of bruteforce-fuzztesting automation code.
Designed for medcored.sys.
*/
#include <windows.h>
#include <winsvc.h>
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "kafl_user.h"
#include "reload.h"

#define SVC_NAME	        __SVC_NAME__
#define SVC_PATH            __SVC_PATH__

typedef enum {false, true} bool;

typedef struct _kAFL_IRP {
    DWORD io_code;
    int32_t in_buf_size;
    int32_t out_buf_size;
    uint8_t* payload;
    bool is_static;
} kAFL_IRP;


kAFL_IRP constraints[] = {
__INTERFACE__
};

int32_t CODE_MAX_LEN = sizeof(constraints) / sizeof(constraints[0]);

int decode_payload(uint8_t* kafl_payload_data, int32_t kafl_payload_size, kAFL_IRP decode_buf[]) 
{
    uint8_t cIndex;
    int decode_len = 0;

    for (int i = 0; i < kafl_payload_size;) {
        cIndex = kafl_payload_data[i];        
        if (cIndex >= CODE_MAX_LEN)
            return decode_len;

        decode_buf[decode_len].io_code = constraints[cIndex].io_code;

        if (kafl_payload_size < i + 1 + constraints[cIndex].in_buf_size)
            if (constraints[cIndex].is_static == true)
                return decode_len;
            else    
                decode_buf[decode_len].in_buf_size = kafl_payload_size - i - 1;
        else
            decode_buf[decode_len].in_buf_size = constraints[cIndex].in_buf_size;

        if (decode_buf[decode_len].in_buf_size != 0) 
            decode_buf[decode_len].payload = &kafl_payload_data[i+1];
        else 
            decode_buf[decode_len].payload = NULL;

        decode_buf[decode_len].out_buf_size = constraints[cIndex].out_buf_size;
        
        i += decode_buf[decode_len].in_buf_size + 1;
        decode_len++;
    }

    return decode_len;
}

void make_readable(uint8_t buf_readable[], uint8_t buf_original[], int32_t buf_size) {

    memset(buf_readable, 0x00, 0xffff);
    memcpy(buf_readable, buf_original, buf_size);
    for (int i = 0; i < buf_size; i++) {
        if (buf_readable[i] <= 0x20 || 0x7f <= buf_readable[i]) {
            buf_readable[i] = '.';
        }
    }
}

int main(int argc, char** argv)
{
    kAFL_IRP decode_buf[0xff];
    uint8_t outBuffer[0xffff];
    uint8_t buf_readable[0xffff];

    hprintf("Starting... %s\n", argv[0]);
    kAFL_payload* payload_buffer = (kAFL_payload*)VirtualAlloc(0, PAYLOAD_SIZE, MEM_COMMIT, PAGE_READWRITE);

    /* open vulnerable driver */
    HANDLE kafl_vuln_handle = NULL;

    /* submit the guest virtual address of the payload buffer */
    hprintf("Submitting buffer address to hypervisor...\n");
    kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (UINT64)payload_buffer);

    /* this hypercall submits the current CR3 value */
    hprintf("Submitting current CR3 value to hypervisor...\n");
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);

    hprintf("Attempting to open vulnerable device file (%s)\n", SVC_PATH);
    kafl_vuln_handle = CreateFile((LPCSTR)SVC_PATH,
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

    if (kAFL_reload(SVC_NAME) != 0) {
        hprintf("[-] Reload error!");
        return 0;
    }

    while (1) {
        hprintf("Memset kAFL_payload at address %lx (size %d)\n", (uint64_t)payload_buffer, PAYLOAD_SIZE);
        memset(payload_buffer, 0xff, PAYLOAD_SIZE);
        
        /* request new payload (blocking) */
        kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);

        make_readable(buf_readable, payload_buffer->data, payload_buffer->size);
        hprintf("origianl payload: %s, original size: %d\n", buf_readable, payload_buffer->size);

        int decode_len = decode_payload(payload_buffer->data, payload_buffer->size, decode_buf);
        hprintf("decode_len: %d\n", decode_len);

        kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);

        for (int i = 0; i < decode_len; i++) {
            make_readable(buf_readable, decode_buf[i].payload, decode_buf[i].in_buf_size);
            hprintf("Injecting data... (iocode: 0x%x, payload: %s, size: %d)\n", decode_buf[i].io_code, buf_readable, decode_buf[i].in_buf_size);

            /* kernel fuzzing */
            DeviceIoControl(kafl_vuln_handle,
                (DWORD)decode_buf[i].io_code,
                (LPVOID)decode_buf[i].payload,
                (DWORD)decode_buf[i].in_buf_size,
                (LPVOID)outBuffer,
                (DWORD)decode_buf[i].out_buf_size,
                NULL,
                NULL
            );
        }
        
        /* inform fuzzer about finished fuzzing iteration */
        hprintf("Injection finished.\n");
        kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
        kAFL_hypercallEx(HYPERCALL_KAFL_RELOAD_COVERED, 0, 0);
        hprintf("Reload finished.\n");
    }

    return 0;
}