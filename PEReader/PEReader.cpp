﻿// PEReader.cpp : Определяет точку входа для приложения.
//

#include "framework.h"
#include "PEReader.h"

#define MAX_LOADSTRING 100

// Глобальные переменные:
HINSTANCE hInst;                                // текущий экземпляр
string szTitle = "PE";                  // Текст строки заголовка
string szWindowClass = "PEREADER";            // имя класса главного окна

// Отправить объявления функций, включенных в этот модуль кода:
ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // TODO: Разместите код здесь.

    // Инициализация глобальных строк
    //LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    //LoadStringW(hInstance, IDC_PEREADER, szWindowClass, MAX_LOADSTRING);
    MyRegisterClass(hInstance);

    // Выполнить инициализацию приложения:
    if (!InitInstance (hInstance, nCmdShow))
    {
        return FALSE;
    }

    HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_PEREADER));

    MSG msg;

    // Цикл основного сообщения:
    while (GetMessage(&msg, nullptr, 0, 0))
    {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    return (int) msg.wParam;
}


//
//  ФУНКЦИЯ: MyRegisterClass()
//
//  ЦЕЛЬ: Регистрирует класс окна.
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEX wcex;

    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style          = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc    = WndProc;
    wcex.cbClsExtra     = 0;
    wcex.cbWndExtra     = 0;
    wcex.hInstance      = hInstance;
    wcex.hIcon          = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_PEREADER));
    wcex.hCursor        = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground  = (HBRUSH)(COLOR_WINDOW+1);
    wcex.lpszMenuName = NULL;
    //MAKEINTRESOURCEW(IDC_PEREADER);
    wcex.lpszClassName  = szWindowClass.c_str();
    wcex.hIconSm        = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

    return RegisterClassEx(&wcex);
}

//
//   ФУНКЦИЯ: InitInstance(HINSTANCE, int)
//
//   ЦЕЛЬ: Сохраняет маркер экземпляра и создает главное окно
//
//   КОММЕНТАРИИ:
//
//        В этой функции маркер экземпляра сохраняется в глобальной переменной, а также
//        создается и выводится главное окно программы.
//
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   hInst = hInstance; // Сохранить маркер экземпляра в глобальной переменной

   HWND hWnd = CreateWindowA(szWindowClass.c_str(), szTitle.c_str(), WS_OVERLAPPEDWINDOW,
       CW_USEDEFAULT, 0, 640, 480, nullptr, nullptr, hInstance, nullptr);

   if (!hWnd)
   {
      return FALSE;
   }

   ShowWindow(hWnd, nCmdShow);
   UpdateWindow(hWnd);

   return TRUE;
}

//
//  ФУНКЦИЯ: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  ЦЕЛЬ: Обрабатывает сообщения в главном окне.
//
//  WM_COMMAND  - обработать меню приложения
//  WM_PAINT    - Отрисовка главного окна
//  WM_DESTROY  - отправить сообщение о выходе и вернуться
//
//
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_CREATE:
    {
        vCreateMenu(hWnd);
        hPEFileName = CreateWindowEx(0, "STATIC", "", WS_CHILD | WS_VISIBLE, 5, 0, 500, 20, hWnd, 0, hInst, NULL);
        hPEStruct = CreateWindowEx(0,
            WC_TREEVIEW,
            "Tree View",
            WS_VISIBLE | WS_CHILD | TVS_HASLINES | TVS_HASBUTTONS | TVS_LINESATROOT,
            5,
            20,
            400,
            400,
            hWnd,
            NULL,
            hInst,
            NULL);
 
    }
        break;
    case WM_COMMAND:
        {
            int wmId = LOWORD(wParam);
            // Разобрать выбор в меню:
            switch (wmId)
            {
                //case IDM_ABOUT:
                //    DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
                //    break;
                case IDM_OPENFILE:
                {
                    HANDLE hPEFile = hOpenPEFile(hWnd);
                    if (hPEFile) {
                        string sCheckMZ = GetUTF8WORDFromPEFile(hPEFile);
                        //ReadFile(PEFile, checkMZ, 2, NULL, NULL);
                        if (sCheckMZ != sMZ) {
                            MessageBox(NULL, "Это не PE файл!", "Предупреждение", MB_ICONWARNING);
                            break;
                        }
                        TreeView_DeleteAllItems(hPEStruct);
                        SetWindowTextA(hPEFileName, ofn.lpstrFile);
                        htiDOS = AddItemToTree(hPEStruct, sDOSHEADER, NULL);
                        htiDOSe_magic = AddItemToTree(hPEStruct, sDOSE_MAGIC + sCheckMZ, htiDOS);
                        //htiDOSstub = AddItemToTree(hPEStruct, sDOSSTUB, NULL);

                        LONG lAddressOfPE = GetLONGFromPEFile(hPEFile, FALSE, 0x3C);
                        string sHexAddressOfPE = GetStringFromLONG(lAddressOfPE, TRUE);
                        string sAddressOfPE = GetStringFromLONG(lAddressOfPE);
                        htiDOSe_lfanew = AddItemToTree(hPEStruct, sDOSE_LFANEW + sHexAddressOfPE + " (" + sAddressOfPE + ")", htiDOS);
                        //htiDOSe_lfanew = GetLONGFromPEFile(PEFile, true, false, 0x3C, hPEStruct, s_DOSe_lfanew, htiDOStitle, true, &addressofPE);
                        htiPE = AddItemToTree(hPEStruct, sPEHEADER, NULL);
                        string sCheckPE = GetUTF8DWORDFromPEFile(hPEFile, 0, lAddressOfPE);
                        if (sCheckPE == "PE") {
                            htiPESignature = AddItemToTree(hPEStruct, sPESIGNATURE + sCheckPE, htiPE);
                        }
                        else {
                            htiPESignature = AddItemToTree(hPEStruct, sPESIGNATURE + sCheckPE, htiPE, TRUE);
                        }
                        //htiPESignature = GetHexWORDFromPEFile(PEFile, false, addressofPE, hPEStruct, s_PESignature, htiPEtitle, true, pe);
                        TreeView_Expand(hPEStruct, htiDOS, TVE_EXPAND);
                        TreeView_Expand(hPEStruct, htiPE, TVE_EXPAND);
                        CloseHandle(hPEFile);
                    }
                    break;
                }
                default:
                    return DefWindowProc(hWnd, message, wParam, lParam);
            }
        }
        break;
    case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hWnd, &ps);
            // TODO: Добавьте сюда любой код прорисовки, использующий HDC...
            EndPaint(hWnd, &ps);
        }
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

// Обработчик сообщений для окна "О программе".
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}

static void vCreateMenu(HWND hwnd) {
    HMENU hMenu = CreateMenu();
    AppendMenu(hMenu, MF_POPUP, IDM_OPENFILE, IDS_OPENFILE);
    SetMenu(hwnd, hMenu);
}

static HANDLE hOpenPEFile(HWND hwnd) {
    HANDLE hf;

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFile = szFile;
    ofn.lpstrFile[0] = '\0';
    ofn.nMaxFile = sizeof(szFile);
    ofn.lpstrFilter = "PE\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = NULL;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (GetOpenFileName(&ofn) == TRUE)
        hf = CreateFile(ofn.lpstrFile,
            GENERIC_READ,
            0,
            (LPSECURITY_ATTRIBUTES)NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            (HANDLE)NULL);
    else hf = NULL;
    return hf;
}


HTREEITEM AddItemToTree(HWND hwndTV, string sItem, HTREEITEM hParent, BOOL bIncorrectElement)
{
    TVINSERTSTRUCT tvins;
    HTREEITEM hme;
    tvins.item.mask = TVIF_TEXT | TVIF_IMAGE | TVIF_DI_SETITEM | TVIF_PARAM;
    if (bIncorrectElement) {
        tvins.item.mask += TVIF_STATE;
        tvins.item.state = TVIS_BOLD;
        tvins.item.stateMask = TVIS_BOLD;
    }
    tvins.item.pszText = const_cast<char*>(sItem.c_str());
    tvins.hInsertAfter = TVI_ROOT;
    if (hParent == NULL)
    {
        tvins.hParent = TVI_ROOT;
    }
    else
    {
        tvins.hParent = hParent;
    }
    hme = TreeView_InsertItem(hwndTV, &tvins);
    return hme;
}

//HTREEITEM GetDataFromPEFile(HANDLE hPEFile, BOOL bReadFromCurrentPose, LONG lDistanceToMove, DWORD nNumberOfBytesToRead, HWND hwndTV, string sLabel, HTREEITEM hParent) {
//    SetFilePointer(hPEFile, lDistanceToMove, NULL, bReadFromCurrentPose);
//    char* psData = new char[nNumberOfBytesToRead];
//    ReadFile(hPEFile, psData, nNumberOfBytesToRead, NULL, NULL);
//    return AddItemToTree(hwndTV, sLabel + psData, hParent);
//    надо бы удаление psData
//}

string GetUTF8WORDFromPEFile(HANDLE hPEFile, BOOL ReadFromCurrentPose, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh) {
    SetFilePointer(hPEFile, lDistanceToMove, lpDistanceToMoveHigh, ReadFromCurrentPose);
    char sData[3] = "";
    ReadFile(hPEFile, sData, 2, NULL, NULL);
    return sData;
}

LONG GetLONGFromPEFile(HANDLE hPEFile, BOOL ReadFromCurrentPose, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh) {
    SetFilePointer(hPEFile, lDistanceToMove, lpDistanceToMoveHigh, ReadFromCurrentPose);
    LONG lData;
    ReadFile(hPEFile, &lData, 4, NULL, NULL);
    return lData;
}

string GetStringFromLONG(LONG lData, BOOL bToHex) {
    if (bToHex) {
        char sHex[8];
        std::snprintf(sHex, 8, "%x", lData);
        return "0x" + string(sHex);
    }
    else {
        char sDec[10];
        std::snprintf(sDec, 10, "%d", lData);
        return sDec;
    }
}

string GetUTF8DWORDFromPEFile(HANDLE hPEFile, BOOL ReadFromCurrentPose, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh) {
    SetFilePointer(hPEFile, lDistanceToMove, lpDistanceToMoveHigh, ReadFromCurrentPose);
    char sData[5] = "";
    ReadFile(hPEFile, sData, 4, NULL, NULL);
    return sData;
}

DWORD GetDWORDFromPEFile(HANDLE hPEFile, BOOL bReadFromCurrentPose, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh) {
    SetFilePointer(hPEFile, lDistanceToMove, lpDistanceToMoveHigh, bReadFromCurrentPose);
    DWORD dwData;
    ReadFile(hPEFile, &dwData, 4, NULL, NULL);
    return dwData;
}

string GetStringFromDWORD(DWORD lData, BOOL bToHex) {
    if (bToHex) {
        char sHex[8];
        std::snprintf(sHex, 8, "%x", lData);
        return string(sHex);
    }
    else {
        char sDec[10];
        std::snprintf(sDec, 10, "%d", lData);
        return sDec;
    }
}



//HTREEITEM GetLONGFromPEFile(HANDLE hPEFile, BOOL bToHex, BOOL ReadFromCurrentPose, LONG lDistanceToMove, HWND hwndTV, string sLabel, HTREEITEM hParent, BOOL bUseBuffer, LONG* plBuffer) {
//    SetFilePointer(hPEFile, lDistanceToMove, NULL, ReadFromCurrentPose);
//    LONG lData;
//    ReadFile(hPEFile, &lData, 4, NULL, NULL);
//    if (bUseBuffer) {
//        *plBuffer = lData;
//    }
//    if (bToHex) {
//        char sHex[8];
//        std::snprintf(sHex, 8, "%x", lData);
//        return AddItemToTree(hwndTV, sLabel + "0x" + sHex, hParent);
//    }
//    else {
//        char sDec[10];
//        std::snprintf(sDec, 10, "%d", lData);
//        return AddItemToTree(hwndTV, sLabel + sDec, hParent);
//    }
//}
//
//HTREEITEM GetHexWORDFromPEFile(HANDLE hPEFile, BOOL bReadFromCurrentPose, LONG lDistanceToMove, HWND hwndTV, string sLabel, HTREEITEM hParent, BOOL bUseBuffer, char* psBuffer) {
//    SetFilePointer(hPEFile, lDistanceToMove, NULL, bReadFromCurrentPose);
//    char szData[3] = "";
//    ReadFile(hPEFile, szData, 2, NULL, NULL);
//    if (bUseBuffer) {
//        memcpy(psBuffer, szData, 3);
//    }
//    return AddItemToTree(hwndTV, sLabel + szData, hParent);
//}