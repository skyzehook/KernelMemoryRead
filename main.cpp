#include <Windows.h>
#include <iostream>


#define IOCTL_SET_PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

int main()
{
    HWND hwnd = FindWindowA(NULL, "AssaultCube");
    DWORD pID = 0;
    GetWindowThreadProcessId(hwnd, &pID);
    std::cout << pID << std::endl;

    LPCWSTR devicePath = L"\\\\.\\KernelMemoryRead";

    HANDLE hDevice = CreateFileW(
        devicePath,
        GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hDevice == INVALID_HANDLE_VALUE)
    {
        std::cout << "failed to open driver error: " << GetLastError() << std::endl;
        std::cout << "driver is not loaded\n";
        return 1;
    }

    DWORD bytes = 0;
    BOOL req = DeviceIoControl(
        hDevice,
        IOCTL_SET_PID,
        &pID,
        sizeof(pID),
        nullptr,
        0,
        &bytes,
        nullptr
    );


    if (!req)
    {
        std::cout << "DeviceIoControl failed error: " << GetLastError() << std::endl;
        CloseHandle(hDevice);
        return 1;
    }


    std::cout << "pID sen to driver!!!!\n";
    Sleep(1500);

    CloseHandle(hDevice);
    return 0;
}
