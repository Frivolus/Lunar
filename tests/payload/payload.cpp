#include <windows.h>

BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        wchar_t path[MAX_PATH]{};
        if (!GetTempPathW(MAX_PATH, path)) return TRUE;

        wcscat_s(path, L"lunar_payload_ok.txt");
        const HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, nullptr,
                                        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) return TRUE;

        const char message[] = "payload execute\n";
        DWORD written = 0;
        WriteFile(file, message, sizeof(message) - 1, &written, nullptr);
        CloseHandle(file);
    }
    return TRUE;
}
