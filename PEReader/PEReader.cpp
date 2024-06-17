// PEReader.cpp : Определяет точку входа для приложения.
//

#include "framework.h"
#include "PEReader.h"

#define MAX_LOADSTRING 100

// Глобальные переменные:
HINSTANCE hInst;                                // текущий экземпляр
string szTitle = "PE32";                  // Текст строки заголовка
string szWindowClass = "PEREADER";            // имя класса главного окна

// Отправить объявления функций, включенных в этот модуль кода:
ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
//INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);

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
    RegisterCodeWndClass(hInstance);

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
       CW_USEDEFAULT, 0, 1280, 960, nullptr, nullptr, hInstance, nullptr);

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
            880,
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
                    OpenFileWithDialogue(hWnd);
                    hPEFile = hOpenPEFile(hWnd);
                    if (hPEFile) {
                        string sCheckMZ = GetUTF8WORDFromPEFile(hPEFile);
                        //ReadFile(PEFile, checkMZ, 2, NULL, NULL);
                        if (sCheckMZ != sMZ) {
                            MessageBox(NULL, "Это не PE файл!", "Предупреждение", MB_ICONWARNING);
                            break;
                        }
                        DestroyCodeWindowsAndButtons();
                        TreeView_DeleteAllItems(hPEStruct);
                        SetWindowTextA(hPEFileName, ofn.lpstrFile);
                        htiDOS = AddItemToTree(hPEStruct, sDOSHEADER, NULL);
                        htiDOSe_magic = AddItemToTree(hPEStruct, sDOSE_MAGIC + sCheckMZ, htiDOS);
                        //htiDOSstub = AddItemToTree(hPEStruct, sDOSSTUB, NULL);
                        lAddressOfPE = GetLONGFromPEFile(hPEFile, FALSE, 0x3C);
                        string sHexAddressOfPE = GetStringFromLONG(lAddressOfPE, TRUE, TRUE);
                        string sAddressOfPE = GetStringFromLONG(lAddressOfPE);
                        htiDOSe_lfanew = AddItemToTree(hPEStruct, sDOSE_LFANEW + sHexAddressOfPE + " (" + sAddressOfPE + ")", htiDOS);
                        htiPE = AddItemToTree(hPEStruct, sPEHEADER, NULL);
                        string sCheckPE = GetUTF8DWORDFromPEFile(hPEFile, 0, lAddressOfPE);
                        if (sCheckPE == "PE") {
                            htiPESignature = AddItemToTree(hPEStruct, sPESIGNATURE + sCheckPE, htiPE);
                            CreateCodeButton(hInst, hWnd, 450, 60, 200, 30, szDOSStubCodeTitle.c_str(), 0x3D, lAddressOfPE - 1);
                            /*CreateWindowA("button", szDOSStubCodeTitle.c_str(), WS_VISIBLE | WS_CHILD | ES_CENTER, 450, 60, 120, 30, hWnd, (HMENU)IDC_OPENDOSSTUB, hInst, NULL);*/
                            htiPEFileHeader = AddItemToTree(hPEStruct, sPEFILEHEADER, htiPE);
                            htiPEFileHeaderMachine = AddItemToTree(hPEStruct, sPEFILEHEADERMACHINE + GetStringFromWORD(GetWORDFromPEFile(hPEFile), TRUE, TRUE), htiPEFileHeader);
                            WORD wNumberOfSections = GetWORDFromPEFile(hPEFile);
                            string sHexNumberOfSections = GetStringFromWORD(wNumberOfSections, TRUE , TRUE);
                            string sNumberOfSections = GetStringFromWORD(wNumberOfSections);
                            htiPEFileHeaderNumberOfSections = AddItemToTree(hPEStruct, sPEFILEHEADERNUMBEROFSECTIONS + sHexNumberOfSections + " (" + sNumberOfSections + ")", htiPEFileHeader);
                            DWORD dwTimeDateStamp = GetDWORDFromPEFile(hPEFile);
                            time_t tTimeDateStamp= time_t(dwTimeDateStamp);
                            char sTimeDateStamp[26];
                            ctime_s(sTimeDateStamp, sizeof(sTimeDateStamp), &tTimeDateStamp);
                            time_t tTimeDateStampBigEndian = time_t(_byteswap_ulong(dwTimeDateStamp));
                            char sTimeDateStampBigEndian[26];
                            ctime_s(sTimeDateStampBigEndian, sizeof(sTimeDateStampBigEndian), &tTimeDateStampBigEndian);
                            htiPEFileHeaderTimeDateStamp = AddItemToTree(hPEStruct, sPEFILEHEADERTIMEDATESTAMP + sTimeDateStamp, htiPEFileHeader);
                            htiPEFileHeaderTimeDateStampBigEndian = AddItemToTree(hPEStruct, sPEFILEHEADERTIMEDATESTAMPBIGENDIAN + sTimeDateStampBigEndian, htiPEFileHeader);
                            DWORD dwPointerToSymbolTable = GetDWORDFromPEFile(hPEFile);
                            htiPEFileHeaderPointerToSymbolTable = AddItemToTree(hPEStruct, sPEFILEHEADERPOINTERTOSYMBOLTABLE + GetStringFromDWORDHexAndDec(dwPointerToSymbolTable), htiPEFileHeader, dwPointerToSymbolTable != 0);
                            DWORD dwNumberOfSymbols = GetDWORDFromPEFile(hPEFile);
                            string sHexNumberOfSymbols = GetStringFromDWORD(dwNumberOfSymbols, TRUE, TRUE);
                            string sNumberOfSymbols = GetStringFromDWORD(dwNumberOfSymbols);
                            htiPEFileHeaderNumberOfSymbols = AddItemToTree(hPEStruct, sPEFILEHEADERNUMBEROFSYMBOLS + sHexNumberOfSymbols + " (" + sNumberOfSymbols + ")", htiPEFileHeader, dwNumberOfSymbols != 0);
                            WORD wSizeOfOptionalHeader = GetWORDFromPEFile(hPEFile);
                            string sHexSizeOfOptionalHeader = GetStringFromWORD(wSizeOfOptionalHeader, TRUE, TRUE);
                            string sSizeOfOptionalHeader = GetStringFromWORD(wSizeOfOptionalHeader);
                            htiPEFileHeaderSizeOfOptionalHeader = AddItemToTree(hPEStruct, sPEFILEHEADERSIZEOFOPTIONALHEADER + sHexSizeOfOptionalHeader + " (" + sSizeOfOptionalHeader + ")", htiPEFileHeader);
                            htiPEFileHeaderCharacteristics = AddItemToTree(hPEStruct, sPEFILEHEADERCHARACTERISTICS + GetStringFromWORD(GetWORDFromPEFile(hPEFile), TRUE, TRUE), htiPEFileHeader);
                            htiOptionalHeader = AddItemToTree(hPEStruct, sOPTIONALHEADER, NULL);
                            WORD wMagic = GetWORDFromPEFile(hPEFile);
                            string sMagic = sUNKNOWN;
                            switch (wMagic) {
                                case (0x10b):
                                    sMagic = sPE32;
                                    break;
                                case (0x20b):
                                    sMagic = sPE32PLUS;
                                    break;
                                case (0x107):
                                    sMagic = sROM;
                                    break;
                            }
                            if (sMagic == sUNKNOWN) {
                                htiOptionalHeaderMagic = AddItemToTree(hPEStruct, sOPTIONALHEADERMAGIC + GetStringFromWORD(wMagic, TRUE, TRUE) + sUNKNOWN, htiOptionalHeader, TRUE);
                            }
                            else {
                                if (sMagic != sPE32) {
                                    htiOptionalHeaderMagic = AddItemToTree(hPEStruct, sOPTIONALHEADERMAGIC + GetStringFromWORD(wMagic, TRUE, TRUE) + sMagic + sNOTSUPPORTED, htiOptionalHeader);
                                }
                                else {
                                    htiOptionalHeaderMagic = AddItemToTree(hPEStruct, sOPTIONALHEADERMAGIC + GetStringFromWORD(wMagic, TRUE, TRUE) + sMagic, htiOptionalHeader);
                                    DWORD dwAddressOfEntryPoint = GetDWORDFromPEFile(hPEFile, TRUE, 14);
                                    htiOptionalHeaderAddressOfEntryPoint = AddItemToTree(hPEStruct, sOPTIONALHEADERADDRESSOFENTRYPOINT + GetStringFromDWORDHexAndDec(dwAddressOfEntryPoint), htiOptionalHeader);
                                    DWORD dwBaseOfCode = GetDWORDFromPEFile(hPEFile);
                                    htiOptionalHeaderBaseOfCode = AddItemToTree(hPEStruct, sOPTIONALHEADERBASEOFCODE + GetStringFromDWORDHexAndDec(dwBaseOfCode), htiOptionalHeader);
                                    DWORD dwBaseOfData = GetDWORDFromPEFile(hPEFile);
                                    htiOptionalHeaderBaseOfData = AddItemToTree(hPEStruct, sOPTIONALHEADERBASEOFDATA + GetStringFromDWORDHexAndDec(dwBaseOfData), htiOptionalHeader);
                                    DWORD dwImageBase = GetDWORDFromPEFile(hPEFile);
                                    if (dwImageBase % 65536 == 0) {
                                        htiOptionalHeaderImageBase = AddItemToTree(hPEStruct, sOPTIONALHEADERIMAGEBASE + GetStringFromDWORDHexAndDec(dwImageBase), htiOptionalHeader);
                                    }
                                    else {
                                        htiOptionalHeaderImageBase = AddItemToTree(hPEStruct, sOPTIONALHEADERIMAGEBASE + GetStringFromDWORDHexAndDec(dwImageBase) + sNOTAMULTIPLE + sOF64KIB, htiOptionalHeader, TRUE);
                                    }
                                    DWORD dwSectionAlignment = GetDWORDFromPEFile(hPEFile);
                                    DWORD dwFileAlignment = GetDWORDFromPEFile(hPEFile);
                                    if (dwSectionAlignment < dwFileAlignment) {
                                        htiOptionalHeaderSectionAlignment = AddItemToTree(hPEStruct, sOPTIONALHEADERSECTIONALIGMENT + GetStringFromDWORDHexAndDec(dwSectionAlignment), htiOptionalHeader, TRUE);
                                    }
                                    else {
                                        htiOptionalHeaderSectionAlignment = AddItemToTree(hPEStruct, sOPTIONALHEADERSECTIONALIGMENT + GetStringFromDWORDHexAndDec(dwSectionAlignment), htiOptionalHeader);
                                    }
                                    htiOptionalHeaderFileAlignment = AddItemToTree(hPEStruct, sOPTIONALHEADERFILEALIGNMENT + GetStringFromDWORDHexAndDec(dwFileAlignment), htiOptionalHeader, !(bIsPowerOfTwo(dwFileAlignment) && dwFileAlignment >= 512 && dwFileAlignment <= 65536));
                                    WORD wMajorVersion = GetWORDFromPEFile(hPEFile);
                                    WORD wMinorVersion = GetWORDFromPEFile(hPEFile);
                                    htiOptionalHeaderMajorOperatingSystemVersion = AddItemToTree(hPEStruct, sOPTIONALHEADERMAJOROPERATINGSYSTEMVERSION + GetStringFromWORDHexAndDec(wMajorVersion), htiOptionalHeader, wMinorVersion > wMajorVersion);
                                    htiOptionalHeaderMinorOperatingSystemVersion = AddItemToTree(hPEStruct, sOPTIONALHEADERMINOROPERATINGSYSTEMVERSION + GetStringFromWORDHexAndDec(wMinorVersion), htiOptionalHeader, wMinorVersion > wMajorVersion);
                                    DWORD dwSizeOfImage = GetDWORDFromPEFile(hPEFile, TRUE, 12);
                                    if (dwSizeOfImage % dwSectionAlignment == 0) {
                                        htiOptionalHeaderSizeOfImage = AddItemToTree(hPEStruct, sOPTIONALHEADERSIZEOFIMAGE + GetStringFromDWORDHexAndDec(dwSizeOfImage), htiOptionalHeader);
                                    }
                                    else {
                                        htiOptionalHeaderSizeOfImage = AddItemToTree(hPEStruct, sOPTIONALHEADERSIZEOFIMAGE + GetStringFromDWORDHexAndDec(dwSizeOfImage) + sNOTAMULTIPLE + sOFSECTIONALIGNMENT, htiOptionalHeader, TRUE);
                                    }
                                    DWORD dwSizeOfHeaders = GetDWORDFromPEFile(hPEFile);
                                    if (dwSizeOfHeaders % dwFileAlignment == 0) {
                                        htiOptionalHeaderSizeOfHeaders = AddItemToTree(hPEStruct, sOPTIONALHEADERSIZEOFHEADERS + GetStringFromDWORDHexAndDec(dwSizeOfHeaders), htiOptionalHeader);
                                    }
                                    else {
                                        htiOptionalHeaderSizeOfHeaders = AddItemToTree(hPEStruct, sOPTIONALHEADERSIZEOFHEADERS + GetStringFromDWORDHexAndDec(dwSizeOfHeaders) + sNOTAMULTIPLE + sOFFILEALIGNMENT, htiOptionalHeader, TRUE);
                                    }
                                    WORD wSubsystem = GetWORDFromPEFile(hPEFile, TRUE, 4);
                                    htiOptionalHeaderSubsystem = AddItemToTree(hPEStruct, sOPTIONALHEADERSUBSYSTEM + GetStringFromWORD(wSubsystem, TRUE, TRUE), htiOptionalHeader);
                                    DWORD NumberOfRvaAndSizes = GetDWORDFromPEFile(hPEFile, TRUE, 22);
                                    htiOptionalHeaderNumberOfRvaAndSizes = AddItemToTree(hPEStruct, sOPTIONALHEADERNUMBEROFRVAANDSIZES + GetStringFromDWORD(NumberOfRvaAndSizes, TRUE, TRUE), htiOptionalHeader, NumberOfRvaAndSizes != 16);
                                    htiOptionalHeaderDataDirectory = AddItemToTree(hPEStruct, sOPTIONALHEADERDATADIRECTORY, htiOptionalHeader);
                                    for (unsigned int i = 0; i < 16; i++) {
                                        DWORD dwVirtualAddress = GetDWORDFromPEFile(hPEFile);
                                        DWORD dwSize = GetDWORDFromPEFile(hPEFile);
                                        htiOptionalHeaderDataDirectorySections[i] = AddItemToTree(hPEStruct, "[" + std::to_string(i) + "]: " + sOPTIONALHEADERDATADIRECTORYSECTIONNAMES[i], htiOptionalHeaderDataDirectory,
                                            (((i == 8) && dwSize != 0) ||
                                            ((i == 7 || i == 15) && dwVirtualAddress != 0 && dwSize != 0)));
                                        AddItemToTree(hPEStruct, sOPTIONALHEADERDATADIRECTORYVIRTUALADDRESS + GetStringFromDWORDHexAndDec(dwVirtualAddress), htiOptionalHeaderDataDirectorySections[i]);
                                        AddItemToTree(hPEStruct, sOPTIONALHEADERDATADIRECTORYSIZE + GetStringFromDWORDHexAndDec(dwSize), htiOptionalHeaderDataDirectorySections[i]);
                                        TreeView_Expand(hPEStruct, htiOptionalHeaderDataDirectorySections[i], TVE_EXPAND);
                                        CreateCodeButton(hInst, hWnd, 450, 100 + 40 * i, 200, 30, sOPTIONALHEADERDATADIRECTORYSECTIONNAMES[i].c_str(), dwVirtualAddress, dwVirtualAddress + dwSize);
                                    }
                                    htiSectionHeader = AddItemToTree(hPEStruct, sSECTIONHEADER, NULL);
                                    for (unsigned int i = 0; i < wNumberOfSections; i++) {
                                        HTREEITEM htiSection = AddItemToTree(hPEStruct, "[" + std::to_string(i) + "]:", htiSectionHeader);
                                        string sName = GetUTF8DWORDLONGFromPEFile(hPEFile);
                                        AddItemToTree(hPEStruct, sSECTIONHEADERNAME + sName, htiSection);
                                        //AddItemToTree(hPEStruct, sSECTIONHEADERPHYSICALADDRESS + GetStringFromDWORDHexAndDec(GetDWORDFromPEFile(hPEFile)), htiSection);
                                        AddItemToTree(hPEStruct, sSECTIONHEADERVIRTUALSIZE + GetStringFromDWORDHexAndDec(GetDWORDFromPEFile(hPEFile)), htiSection);
                                        AddItemToTree(hPEStruct, sSECTIONHEADERVIRTUALADDRESS + GetStringFromDWORDHexAndDec(GetDWORDFromPEFile(hPEFile)), htiSection);
                                        DWORD dwSizeOfRawData = GetDWORDFromPEFile(hPEFile);
                                        AddItemToTree(hPEStruct, sSECTIONHEADERSIZEOFRAWDATA + GetStringFromDWORDHexAndDec(dwSizeOfRawData), htiSection);
                                        DWORD dwPointerToRawData = GetDWORDFromPEFile(hPEFile);
                                        AddItemToTree(hPEStruct, sSECTIONHEADERPOINTERTORAWDATA + GetStringFromDWORDHexAndDec(dwPointerToRawData), htiSection);
                                        AddItemToTree(hPEStruct, sSECTIONHEADERPOINTERTORELOCATIONS + GetStringFromDWORDHexAndDec(GetDWORDFromPEFile(hPEFile)), htiSection);
                                        AddItemToTree(hPEStruct, sSECTIONHEADERPOINTERTOLINENUMBERS + GetStringFromDWORDHexAndDec(GetDWORDFromPEFile(hPEFile)), htiSection);
                                        AddItemToTree(hPEStruct, sSECTIONHEADERNUMBEROFRELOCATIONS + GetStringFromWORDHexAndDec(GetWORDFromPEFile(hPEFile)), htiSection);
                                        AddItemToTree(hPEStruct, sSECTIONHEADERNUMBEROFLINENUMBERS + GetStringFromWORDHexAndDec(GetWORDFromPEFile(hPEFile)), htiSection);
                                        AddItemToTree(hPEStruct, sSECTIONHEADERCHARACTERISTICS + GetStringFromDWORD(GetDWORDFromPEFile(hPEFile), TRUE, TRUE), htiSection);
                                        TreeView_Expand(hPEStruct, htiSection, TVE_EXPAND);
                                        CreateCodeButton(hInst, hWnd, 700, 60 + 40*i, 120, 30, sName.c_str(), dwPointerToRawData, dwPointerToRawData + dwSizeOfRawData);
                                    }
                                }
                            }
                        }
                        else {
                            htiPESignature = AddItemToTree(hPEStruct, sPESIGNATURE + sCheckPE, htiPE, TRUE);
                        }
                        TreeView_Expand(hPEStruct, htiDOS, TVE_EXPAND);
                        TreeView_Expand(hPEStruct, htiPE, TVE_EXPAND);
                        TreeView_Expand(hPEStruct, htiPEFileHeader, TVE_EXPAND);
                        TreeView_Expand(hPEStruct, htiOptionalHeader, TVE_EXPAND);
                        TreeView_Expand(hPEStruct, htiOptionalHeaderDataDirectory, TVE_EXPAND);
                        TreeView_Expand(hPEStruct, htiSectionHeader, TVE_EXPAND);
                        CloseHandle(hPEFile);
                    }
                    break;
                }
                case IDC_CLICKCODEBUTTON:
                {
                    size_t unCountOfCodeButtons = hCodeButtons.size();
                    for (size_t i = 0; i < unCountOfCodeButtons; i++) {
                        if ((HWND)lParam == hCodeButtons[i].hCodeButton) {
                            InitCodeWnd(hInst, i);
                        }
                    }
                    /*InitCodeWnd(hInst, &hDOSStubCodeWnd, szDOSStubCodeTitle.c_str(), 0x3D, lAddressOfPE - 1);*/
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
//INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
//{
//    UNREFERENCED_PARAMETER(lParam);
//    switch (message)
//    {
//    case WM_INITDIALOG:
//        return (INT_PTR)TRUE;
//
//    case WM_COMMAND:
//        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
//        {
//            EndDialog(hDlg, LOWORD(wParam));
//            return (INT_PTR)TRUE;
//        }
//        break;
//    }
//    return (INT_PTR)FALSE;
//}

static VOID vCreateMenu(HWND hwnd) {
    HMENU hMenu = CreateMenu();
    AppendMenu(hMenu, MF_POPUP, IDM_OPENFILE, IDS_OPENFILE);
    SetMenu(hwnd, hMenu);
}

static BOOL OpenFileWithDialogue(HWND hwnd) {
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
    return GetOpenFileName(&ofn);
}

static HANDLE hOpenPEFile(HWND hwnd) {
    HANDLE hf;
    hf = CreateFile(ofn.lpstrFile,
        GENERIC_READ,
        0,
        (LPSECURITY_ATTRIBUTES)NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        (HANDLE)NULL);
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

string GetUTF8DWORDLONGFromPEFile(HANDLE hPEFile, BOOL ReadFromCurrentPose, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh) {
    SetFilePointer(hPEFile, lDistanceToMove, lpDistanceToMoveHigh, ReadFromCurrentPose);
    char sData[9] = "";
    ReadFile(hPEFile, sData, 8, NULL, NULL);
    return sData;
}

string GetStringFromLONG(LONG lData, BOOL bToHex, BOOL bWriteWith0x) {
    if (bToHex) {
        char sHex[9] = "";
        std::snprintf(sHex, 8, "%07X", lData);
        if (bWriteWith0x){
            return "0x" + string(sHex);
        }
        else{
            return string(sHex);
        }
    }
    else {
        char sDec[12] = "";
        std::snprintf(sDec, 11, "%d", lData);
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

WORD GetWORDFromPEFile(HANDLE hPEFile, BOOL bReadFromCurrentPose, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh) {
    SetFilePointer(hPEFile, lDistanceToMove, lpDistanceToMoveHigh, bReadFromCurrentPose);
    WORD wData;
    ReadFile(hPEFile, &wData, 2, NULL, NULL);
    return wData;
}

string GetStringFromDWORD(DWORD lData, BOOL bToHex, BOOL bWriteWith0x) {
    if (bToHex) {
        char sHex[9] = "";
        std::snprintf(sHex, 9, "%08X", lData);
        if (bWriteWith0x) {
            return "0x" + string(sHex);
        }
        else {
            return string(sHex);
        }
    }
    else {
        char sDec[11] = "";
        std::snprintf(sDec, 10, "%d", lData);
        return sDec;
    }
}

string GetStringFromDWORDHexAndDec(DWORD lData) {
    char sHex[9] = "";
    char sDec[11] = "";
    std::snprintf(sHex, 9, "%08X", lData);
    std::snprintf(sDec, 10, "%d", lData);
    return "0x" + string(sHex) + " (" + sDec + ")";
}

string GetStringFromWORD(WORD wData, BOOL bToHex, BOOL bWriteWith0x) {
    if (bToHex) {
        char sHex[5] = "";
        std::snprintf(sHex, 5, "%04X", wData);
        if (bWriteWith0x) {
            return "0x" + string(sHex);
        }
        else {
            return string(sHex);
        }
    }
    else {
        char sDec[7] = "";
        std::snprintf(sDec, 6, "%d", wData);
        return sDec;
    }
}

string GetStringFromWORDHexAndDec(WORD lData) {
    char sHex[5] = "";
    char sDec[7] = "";
    std::snprintf(sHex, 5, "%04X", lData);
    std::snprintf(sDec, 6, "%d", lData);
    return "0x" + string(sHex) + " (" + sDec + ")";
}

BYTE GetBYTEFromPEFile(HANDLE hPEFile, BOOL ReadFromCurrentPose, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh) {
    SetFilePointer(hPEFile, lDistanceToMove, lpDistanceToMoveHigh, ReadFromCurrentPose);
    BYTE BData;
    ReadFile(hPEFile, &BData, 1, NULL, NULL);
    return BData;
}

inline string GetUTF8FromBYTE(BYTE byData) {
    return string(1, byData);
}

string GetStringFromBYTE(BYTE BData, BOOL bToHex, BOOL bWriteWith0x) {
    if (bToHex) {
        char sHex[3];
        std::snprintf(sHex, 3, "%03X", BData);
        if (bWriteWith0x) {
            return "0x" + string(sHex);
        }
        else {
            return string(sHex);
        }
    }
    else {
        char sDec[4];
        std::snprintf(sDec, 3, "%d", BData);
        return sDec;
    }
}

//ULONGLONG GetULONGLONGFromPEFile(HANDLE hPEFile, BOOL bReadFromCurrentPose, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh) {
//    SetFilePointer(hPEFile, lDistanceToMove, lpDistanceToMoveHigh, bReadFromCurrentPose);
//    ULONGLONG ullData;
//    ReadFile(hPEFile, &ullData, 8, NULL, NULL);
//    return ullData;
//}
//
//string GetStringFromULONGLONG(ULONGLONG ullData, BOOL bToHex, BOOL bWriteWith0x) {
//    if (bToHex) {
//        char sHex[17];
//        std::snprintf(sHex, 16, "%LX", ullData);
//        if (bWriteWith0x) {
//            return "0x" + string(sHex);
//        }
//        else {
//            return string(sHex);
//        }
//    }
//    else {
//        char sDec[21];
//        std::snprintf(sDec, 20, "%u", ullData);
//        return sDec;
//    }
//}

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

ATOM RegisterCodeWndClass(HINSTANCE hInstance)
{
    WNDCLASSEX wcex;

    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = CodeWndProc;
    wcex.cbClsExtra = 0;
    wcex.cbWndExtra = sizeof(LONG);
    wcex.hInstance = hInstance;
    wcex.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_PEREADER));
    wcex.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszMenuName = NULL;
    //MAKEINTRESOURCEW(IDC_PEREADER);
    wcex.lpszClassName = szCodeWndClass.c_str();
    wcex.hIconSm = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

    return RegisterClassEx(&wcex);
}

void CreateCodeButton(HINSTANCE hInstance, HWND hWndParent, int x, int y, int nWidth, int nHeight, string sTitle, LONG lBegOfCode, LONG lEndOfCode) {
    size_t unIndexOfButton = hCodeButtons.size();
  /*  CREATESTRUCT csIndexOfButton;
    csIndexOfButton.lpCreateParams = &unIndexOfButton;*/
    HWND hButton = CreateWindowA("button", sTitle.c_str(), WS_VISIBLE | WS_CHILD | ES_CENTER, x, y, nWidth, nHeight, hWndParent, (HMENU)IDC_CLICKCODEBUTTON, hInstance, NULL);
    hCodeButtons.push_back(structCodeButton{
        hButton,
        NULL,
        lBegOfCode,
        lEndOfCode,
        sTitle});
    if (lBegOfCode == lEndOfCode) {
        EnableWindow(hButton, FALSE);
    }

        //LONG laAdresses[2] = { lBegOfCode , lEndOfCode };
        //CREATESTRUCT csAdresses;
        //csAdresses.lpCreateParams = &laAdresses;
    return;
}

BOOL InitCodeWnd(HINSTANCE hInstance, size_t unIndexOfButton) {
    //LONG laAdresses[2] = { lBegOfCode , lEndOfCode };
    //CREATESTRUCT csAdresses;
    //csAdresses.lpCreateParams = &laAdresses;
    CREATESTRUCT csIndexOfButton;
    csIndexOfButton.lpCreateParams = &unIndexOfButton;
    HWND *hWnd = &hCodeButtons[unIndexOfButton].hCodeWnd;
    if (*hWnd) {
        DestroyWindow(*hWnd);
    }
    *hWnd = CreateWindowA(szCodeWndClass.c_str(), hCodeButtons[unIndexOfButton].sTitle.c_str(), WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, 0, 1200, 520, nullptr, nullptr, hInstance, &csIndexOfButton);

    if (!*hWnd)
    {
        return FALSE;
    }

    ShowWindow(*hWnd, SW_NORMAL);
    UpdateWindow(*hWnd);

    return TRUE;
}

LRESULT CALLBACK CodeWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_CREATE:
    {
        LPCREATESTRUCT create_struct = reinterpret_cast<LPCREATESTRUCT>(lParam);
        size_t unIndexOfButton = **(size_t**)(create_struct->lpCreateParams);
        SetWindowLong(hWnd, 0, (LONG)unIndexOfButton);
        //LONG lBegOfCode = **(LONG**)(create_struct->lpCreateParams);
        //LONG lEndOfCode = *(*(LONG**)(create_struct->lpCreateParams)+1);
        DWORD lBegOfCode = hCodeButtons[unIndexOfButton].lBegOfCode;
        DWORD lEndOfCode = hCodeButtons[unIndexOfButton].lEndOfCode;
        HWND *hForwardButton = &hCodeButtons[unIndexOfButton].hForwardButton;
        HWND* hBackButton = &hCodeButtons[unIndexOfButton].hBackButton;
        DWORD* dwCountOfPages = &hCodeButtons[unIndexOfButton].dwCountOfPages;
        *dwCountOfPages = DWORD(ceil(((lEndOfCode - lBegOfCode + 1)) / (16*nRowsOnPage))) + 1;
        *hForwardButton = CreateWindowA("button", sFORWARD.c_str(), WS_VISIBLE | WS_CHILD | ES_CENTER, 1050, 50, 100, 30, hWnd, (HMENU)IDC_FORWARDBUTTON, hInst, NULL);
        *hBackButton = CreateWindowA("button", sBACK.c_str(), WS_VISIBLE | WS_CHILD | ES_CENTER, 1050, 120, 100, 30, hWnd, (HMENU)IDC_BACKBUTTON, hInst, NULL);
        OpenPage(hWnd, 0);
        break;
    }
    case WM_PAINT:
    {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);
        // TODO: Добавьте сюда любой код прорисовки, использующий HDC...
        EndPaint(hWnd, &ps);
    }
    break;
    case WM_COMMAND:
    {
        int wmId = LOWORD(wParam);
        // Разобрать выбор в меню:
        switch (wmId)
        {
        case IDC_FORWARDBUTTON:
        {
            size_t unIndexOfButton = (size_t)GetWindowLong(hWnd, 0);
            LONG* dwPage = &hCodeButtons[unIndexOfButton].dwPage;
            *dwPage += 1;
            OpenPage(hWnd, *dwPage);
            break;
        }
        case IDC_BACKBUTTON:
        {
            size_t unIndexOfButton = (size_t)GetWindowLong(hWnd, 0);
            LONG* dwPage = &hCodeButtons[unIndexOfButton].dwPage;
            *dwPage -= 1;
            OpenPage(hWnd, *dwPage);
            break;
        }
        }
    }
    case WM_DESTROY:
        return 0;
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

VOID DestroyCodeWindowsAndButtons() {

    for (unsigned int i = 0; i < hCodeButtons.size(); i++) {
        DestroyWindow(hCodeButtons[i].hCodeWnd);
        DestroyWindow(hCodeButtons[i].hCodeButton);
    }
    hCodeButtons.clear();
    return;
}

VOID AddItemToTable(HWND hWnd, string sItem, int nLine, int nColumn)
{
    LVITEM lvi = { 0 };
    lvi.mask = LVIF_TEXT;
    lvi.state = 0;
    lvi.stateMask = 0;
    lvi.iItem = nLine;
    lvi.pszText = const_cast<char*>(sItem.c_str());
    if (nColumn == 0) {
        ListView_InsertItem(hWnd, &lvi);
    }
    else {
        lvi.iSubItem = nColumn;
        ListView_SetItem(hWnd, &lvi);
    }
    return;
}

inline BOOL bIsPowerOfTwo(int nData) {
    return nData && !(nData & (nData - 1));
}

BOOL OpenPage(HWND hWnd, LONG dwPage) {
    size_t unIndexOfButton = (size_t)GetWindowLong(hWnd, 0);
    HWND* hCodeTable = &hCodeButtons[unIndexOfButton].hCodeTable;
    LONG lBegOfCode = nRowsOnPage * dwPage * 16 + hCodeButtons[unIndexOfButton].lBegOfCode;
    BOOL bBegOfCode = lBegOfCode - dwPage <= hCodeButtons[unIndexOfButton].lBegOfCode;
    BOOL bEndOfCode = ((lBegOfCode + nRowsOnPage * 16) >= hCodeButtons[unIndexOfButton].lEndOfCode);
    HWND* hForwardButton = &hCodeButtons[unIndexOfButton].hForwardButton;
    HWND* hBackButton = &hCodeButtons[unIndexOfButton].hBackButton;
    HWND* hCountOfPages = &hCodeButtons[unIndexOfButton].hCountOfPages;
    *hCountOfPages = CreateWindowEx(0, "STATIC", (std::to_string(dwPage + 1) + " / " + std::to_string(hCodeButtons[unIndexOfButton].dwCountOfPages)).c_str(), WS_CHILD | WS_VISIBLE, 1050, 90, 100, 15, hWnd, 0, hInst, NULL);
    if (bBegOfCode) {
        EnableWindow(*hBackButton, FALSE);
    }
    else {
        EnableWindow(*hBackButton, TRUE);
    }
    if (bEndOfCode) {
        EnableWindow(*hForwardButton, FALSE);
    }
    else {
        EnableWindow(*hForwardButton, TRUE);
    }
    LONG lEndOfCode = bEndOfCode ? hCodeButtons[unIndexOfButton].lEndOfCode : lBegOfCode + nRowsOnPage*16 - 1;
    DestroyWindow(*hCodeTable);
    *hCodeTable = CreateWindowA(
        WC_LISTVIEW,
        "",
        WS_VISIBLE | WS_CHILD | LVS_REPORT | WS_BORDER,
        0, 0,
        1037,
        480,
        hWnd,
        NULL,
        hInst,
        NULL);

    LVCOLUMN lvc;
    BYTE iCol;

    lvc.mask = LVCF_FMT | LVCFMT_CENTER | LVCF_TEXT;
    lvc.iSubItem = 0;
    lvc.pszText = nullptr;
    lvc.cx = 60;
    lvc.fmt = LVCFMT_CENTER;
    if (ListView_InsertColumn(*hCodeTable, 0, &lvc) == -1)
        return FALSE;
    lvc.cx = 30;
    lvc.mask += LVCF_SUBITEM;
    for (BYTE i = 0; i < 2; i++) {
        for (iCol = 1; iCol <= 16; iCol++)
        {
            char sHex[2] = { (iCol - 1 < 10) ? '0' + iCol - 1 : 'a' - 10 + iCol - 1, '\0' };
            lvc.iSubItem = i * 17 + iCol;
            lvc.pszText = sHex;

            if (ListView_InsertColumn(*hCodeTable, i * 17 + iCol, &lvc) == -1)
                return FALSE;
        }
        if (i == 0) {
            lvc.iSubItem = 17;
            lvc.pszText = nullptr;
            if (ListView_InsertColumn(*hCodeTable, 17, &lvc) == -1)
                return FALSE;
            lvc.cx = 28;
        }
    }
    BYTE nTailOfBytes = lBegOfCode % 16;
    if (nTailOfBytes != 0) {
        AddItemToTable(*hCodeTable, GetStringFromLONG(lBegOfCode - nTailOfBytes, TRUE), 0, 0);
        for (BYTE i = 1; i < nTailOfBytes; i++) {
            AddItemToTable(*hCodeTable, "", 1, i);
            AddItemToTable(*hCodeTable, "", 1, 17 + i);
        }
    }
    //LONG nNumberOfBytes = lEndOfCode - lBegOfCode;
    LONG nByte = lBegOfCode;
    BYTE nColumn = 1 + nTailOfBytes;
    LONG lRow = 0;
    hPEFile = hOpenPEFile(hPEFileName);
    SetFilePointer(hPEFile, lBegOfCode, NULL, 0);
    while (nByte <= lEndOfCode) {
        if (nColumn == 1) {
            AddItemToTable(*hCodeTable, GetStringFromLONG(nByte, TRUE), lRow, 0);
        }
        BYTE BBYTEFromPEFile = GetBYTEFromPEFile(hPEFile, TRUE, 0);
        AddItemToTable(*hCodeTable, GetStringFromBYTE(BBYTEFromPEFile, TRUE), lRow, nColumn);
        AddItemToTable(*hCodeTable, GetUTF8FromBYTE(BBYTEFromPEFile), lRow, 17 + nColumn);
        nColumn += 1;
        if (nColumn == 17) {
            nColumn = 1;
            lRow++;
        }
        nByte++;
    }
    //DWORD nNumberOfRows = DWORD(ceil(nNumberOfBytes / 16));
    //for (DWORD i = 0; i < nNumberOfRows; i++)
    //{
    //    AddItemToTable(*hCodeTable, GetStringFromLONG(lBegOfCode + i * 16, TRUE), i, 0);
    //    for (DWORD j = 1; j < 17; i++) {
    //        if (nByte == nNumberOfBytes) {
    //            break;
    //        }
    //        BYTE BBYTEFromPEFile = GetBYTEFromPEFile(hPEFile, TRUE, 0);
    //        AddItemToTable(*hCodeTable, GetStringFromBYTE(BBYTEFromPEFile, TRUE), i, j);
    //        AddItemToTable(*hCodeTable, GetUTF8FromBYTE(BBYTEFromPEFile), i, 17 + j);
    //        nByte += 1;
    //    }
    //}
    CloseHandle(hPEFile);
    return TRUE;
}