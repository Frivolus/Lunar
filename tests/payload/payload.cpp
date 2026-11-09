#include <windows.h>

extern "C" BOOL WINAPI DllMain(HMODULE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        const HANDLE file = CreateFileW(L"C:\\dev\\lunar_payload_ok.txt", GENERIC_WRITE, 0,
                                        nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) return TRUE;

        const char message[] = "payload execute\n";
        DWORD written = 0;
        WriteFile(file, message, sizeof(message) - 1, &written, nullptr);
        CloseHandle(file);
    }
    return TRUE;
}
