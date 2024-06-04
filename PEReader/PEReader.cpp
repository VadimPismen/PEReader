// PEReader.cpp : Определяет точку входа для приложения.
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
        hPEStruct = CreateWindowEx(0,
            WC_TREEVIEW,
            "Tree View",
            WS_VISIBLE | WS_CHILD | TVS_HASLINES | TVS_HASBUTTONS | TVS_LINESATROOT,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
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
                    HANDLE PEFile = hOpenPEFile(hWnd);
                    if (PEFile) {
                        char checkMZ[3] = "";
                        ReadFile(PEFile, checkMZ, 2, NULL, NULL);
                        if (checkMZ != s_MZ) {
                            MessageBox(NULL, "Это не PE файл!", "Предупреждение", MB_ICONWARNING);
                            break;
                        }
                        TreeView_DeleteAllItems(hPEStruct);
                        htiDOStitle = AddItemToTree(hPEStruct, s_DOStitle, NULL);
                        htiDOSe_magic = AddItemToTree(hPEStruct, s_DOSe_magic + checkMZ, htiDOStitle);
                        LONG addressofPE;
                        htiDOSe_lfanew = vGetLONGFromPEFile(PEFile, true, false, 0x3C, hPEStruct, s_DOSe_lfanew, htiDOStitle, true, &addressofPE);
                        htiPEtitle = AddItemToTree(hPEStruct, s_PEtitle, NULL);
                        char pe[3];
                        htiPESignature = vGetHexWORDFromPEFile(PEFile, false, addressofPE, hPEStruct, s_PESignature, htiPEtitle, true, pe);
                        TreeView_Expand(hPEStruct, htiDOStitle, TVE_EXPAND);
                        TreeView_Expand(hPEStruct, htiPEtitle, TVE_EXPAND);
                        CloseHandle(PEFile);
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


HTREEITEM AddItemToTree(HWND hwndTV, string lpszItem, HTREEITEM hParent)
{
    TVITEM tParent;
    TVINSERTSTRUCT tvins;
    HTREEITEM hme;
    // set the parameters of ITEM
    tvins.item.mask = TVIF_TEXT | TVIF_IMAGE | TVIF_DI_SETITEM | TVIF_PARAM;
    tvins.item.pszText = const_cast<char*>(lpszItem.c_str());
    tvins.hInsertAfter = TVI_ROOT;
    if (hParent == NULL)
    {
        tvins.hParent = TVI_ROOT;
    }
    else
    {
        tvins.hParent = hParent;
    }
    // call the function key TreeView_InsertItem
    hme = TreeView_InsertItem(hwndTV, &tvins);
    return hme;
}

HTREEITEM vGetDataFromPEFile(HANDLE PEFile, BOOL ReadFromCurrentPose, LONG lDistanceToMove, DWORD nNumberOfBytesToRead, HWND hwndTV, string label, HTREEITEM hParent) {
    SetFilePointer(PEFile, lDistanceToMove, NULL, ReadFromCurrentPose);
    char* data = new char[nNumberOfBytesToRead];
    ReadFile(PEFile, data, nNumberOfBytesToRead, NULL, NULL);
    return AddItemToTree(hwndTV, label + data, hParent);
}

HTREEITEM vGetLONGFromPEFile(HANDLE PEFile, BOOL tohex, BOOL ReadFromCurrentPose, LONG lDistanceToMove, HWND hwndTV, string label, HTREEITEM hParent, BOOL usebuffer, LONG* Buffer) {
    SetFilePointer(PEFile, lDistanceToMove, NULL, ReadFromCurrentPose);
    LONG data;
    ReadFile(PEFile, &data, 4, NULL, NULL);
    if (usebuffer) {
        *Buffer = data;
    }
    if (tohex) {
        char hex[8];
        std::snprintf(hex, 8, "%x", data);
        return AddItemToTree(hwndTV, label + "0x" + hex, hParent);
    }
    else {
        char dec[10];
        std::snprintf(dec, 10, "%d", data);
        return AddItemToTree(hwndTV, label + dec, hParent);
    }
}

HTREEITEM vGetHexWORDFromPEFile(HANDLE PEFile, BOOL ReadFromCurrentPose, LONG lDistanceToMove, HWND hwndTV, string label, HTREEITEM hParent, BOOL usebuffer, char *Buffer) {
    SetFilePointer(PEFile, lDistanceToMove, NULL, ReadFromCurrentPose);
    char data[3] = "";
    ReadFile(PEFile, data, 2, NULL, NULL);
    if (usebuffer) {
        memcpy(Buffer, data, 3);
    }
    return AddItemToTree(hwndTV, label + data, hParent);
}
