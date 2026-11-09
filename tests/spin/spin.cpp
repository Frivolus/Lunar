#include <windows.h>
#include <cstdio>

int main() {
    std::printf("pid=%lu\n", GetCurrentProcessId());
    std::fflush(stdout);

    volatile unsigned long long counter = 0;
    for (;;) ++counter;
    return 0;
}