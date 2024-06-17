#pragma once

#include "resource.h"
#include <string>
#include <commdlg.h>
#include <CommCtrl.h>
#include <ctime>
#include <vector>

#define IDM_OPENFILE	2
#define IDS_OPENFILE	"Открыть файл"

using std::string;

OPENFILENAME ofn;
char szFile[260];

const string sMZ = "MZ";
const string sDOSHEADER = "DOS header:";
const string sDOSE_MAGIC = "e_magic = ";
const string sDOSE_LFANEW = "e_lfanew = ";
const string sDOSSTUB = "DOS stub:";
const string sPEHEADER = "PE header:";
const string sPESIGNATURE = "Signature = ";
const string sPEFILEHEADER = "File header:";
const string sPEFILEHEADERMACHINE = "Machine = ";
const string sPEFILEHEADERNUMBEROFSECTIONS = "NumberOfSections = ";
const string sPEFILEHEADERTIMEDATESTAMP = "TimeDateStamp = ";
const string sPEFILEHEADERTIMEDATESTAMPBIGENDIAN = "TimeDateStamp (Big-endian) = ";
const string sPEFILEHEADERPOINTERTOSYMBOLTABLE = "PointerToSymbolTable = ";
const string sPEFILEHEADERNUMBEROFSYMBOLS = "NumberOfSymbols = ";
const string sPEFILEHEADERSIZEOFOPTIONALHEADER = "SizeOfOptionalHeader = ";
const string sPEFILEHEADERCHARACTERISTICS = "Characteristics = ";
const string sOPTIONALHEADER = "Optional header :";
const string sOPTIONALHEADERMAGIC = "Magic = ";
const string sPE32 = " (PE32)";
const string sPE32PLUS = " (PE32+)";
const string sROM = " (ROM)";
const string sUNKNOWN = " (UNKNOWN)";
const string sNOTSUPPORTED = " (READING IS NOT SUPPORTED)";
const string sOPTIONALHEADERADDRESSOFENTRYPOINT = "AddressOfEntryPoint = ";
const string sOPTIONALHEADERBASEOFCODE = "BaseOfCode = ";
const string sOPTIONALHEADERBASEOFDATA = "BaseOfData = ";
const string sOPTIONALHEADERIMAGEBASE = "ImageBase = ";
const string sNOTAMULTIPLE = "(NOT A MULTIPLE OF ";
const string sOF64KIB = "64 KiB)";
const string sB = " bytes";
const string sOFSECTIONALIGNMENT = "SectionAlignment)";
const string sOFFILEALIGNMENT = "FileAlignment)";
const string sOPTIONALHEADERSECTIONALIGMENT = "SectionAligment = ";
const string sOPTIONALHEADERFILEALIGNMENT = "FileAlignment = ";
const string sOPTIONALHEADERMAJOROPERATINGSYSTEMVERSION = "MajorOperatingSystemVersion = ";
const string sOPTIONALHEADERMINOROPERATINGSYSTEMVERSION = "MinorOperatingSystemVersion = ";
const string sOPTIONALHEADERSIZEOFIMAGE = "SizeOfImage = ";
const string sOPTIONALHEADERSIZEOFHEADERS = "SizeOfHeaders = ";
const string sOPTIONALHEADERSUBSYSTEM = "Subsystem = ";
const string sOPTIONALHEADERNUMBEROFRVAANDSIZES = "NumberOfRvaAndSizes = ";
const string sOPTIONALHEADERDATADIRECTORY = "DataDirectory:";
const string sOPTIONALHEADERDATADIRECTORYSECTIONNAMES[16] =
{"Export Table", "Import Table", "Resource Table", "Exception Table",
"Certificate Table", "Base Relocation Table", "Debug", "Architecture",
"Global Ptr", "TLS Table", "Load Config Table", "Bound Import",
"IAT", "Delay Import Descriptor", "CLR Runtime Header", "Reserved"};
const string sOPTIONALHEADERDATADIRECTORYVIRTUALADDRESS = "VirtualAddress = ";
const string sOPTIONALHEADERDATADIRECTORYSIZE = "Size = ";
const string sSECTIONHEADER = "Section header:";
const string sSECTIONHEADERNAME = "Name = ";
//const string sSECTIONHEADERPHYSICALADDRESS = "PhysicalAddress = ";
const string sSECTIONHEADERVIRTUALSIZE = "VirtualSize = ";
const string sSECTIONHEADERVIRTUALADDRESS = "VirtualAddress = ";
const string sSECTIONHEADERSIZEOFRAWDATA = "SizeOfRawData = ";
const string sSECTIONHEADERPOINTERTORAWDATA = "PointerToRawData = ";
const string sSECTIONHEADERPOINTERTORELOCATIONS = "PointerToRelocations = ";
const string sSECTIONHEADERPOINTERTOLINENUMBERS = "PointerToLinenumbers = ";
const string sSECTIONHEADERNUMBEROFRELOCATIONS = "NumberOfRelocations = ";
const string sSECTIONHEADERNUMBEROFLINENUMBERS = "NumberOfLinenumbers = ";
const string sSECTIONHEADERCHARACTERISTICS = "Characteristics = ";


LONG lAddressOfPE;

#define IDC_CLICKCODEBUTTON			200
#define IDC_FORWARDBUTTON			201
#define IDC_BACKBUTTON				202

const string sFORWARD = "Forward";
const string sBACK = "Back";

const string szCodeWndClass = "CODEWND";

struct structCodeButton {
	HWND hCodeButton;
	HWND hCodeWnd;
	LONG lBegOfCode;
	LONG lEndOfCode;
	string sTitle;
	LONG dwPage = 0;
	HWND hCodeTable = NULL;
	HWND hForwardButton = NULL;
	HWND hBackButton = NULL;
	DWORD dwCountOfPages = 0;
	HWND hCountOfPages = NULL;
};

std::vector<structCodeButton> hCodeButtons;

LONG nRowsOnPage = 300;
HWND hPEFileName;
HWND hPEStruct;
HTREEITEM htiDOS;
HTREEITEM htiDOSe_magic;
HTREEITEM htiDOSe_lfanew;
HTREEITEM htiDOSstub;
HTREEITEM htiPE;
HTREEITEM htiPESignature;
HTREEITEM htiPEFileHeader;
HTREEITEM htiPEFileHeaderMachine;
HTREEITEM htiPEFileHeaderNumberOfSections;
HTREEITEM htiPEFileHeaderTimeDateStamp;
HTREEITEM htiPEFileHeaderTimeDateStampBigEndian;
HTREEITEM htiPEFileHeaderPointerToSymbolTable;
HTREEITEM htiPEFileHeaderNumberOfSymbols;
HTREEITEM htiPEFileHeaderSizeOfOptionalHeader;
HTREEITEM htiPEFileHeaderCharacteristics;
HTREEITEM htiOptionalHeader;
HTREEITEM htiOptionalHeaderMagic;
HTREEITEM htiOptionalHeaderAddressOfEntryPoint;
HTREEITEM htiOptionalHeaderBaseOfCode;
HTREEITEM htiOptionalHeaderBaseOfData;
HTREEITEM htiOptionalHeaderImageBase;
HTREEITEM htiOptionalHeaderSectionAlignment;
HTREEITEM htiOptionalHeaderFileAlignment;
HTREEITEM htiOptionalHeaderMajorOperatingSystemVersion;
HTREEITEM htiOptionalHeaderMinorOperatingSystemVersion;
HTREEITEM htiOptionalHeaderSizeOfImage;
HTREEITEM htiOptionalHeaderSizeOfHeaders;
HTREEITEM htiOptionalHeaderSubsystem;
HTREEITEM htiOptionalHeaderNumberOfRvaAndSizes;
HTREEITEM htiOptionalHeaderDataDirectory;
HTREEITEM htiOptionalHeaderDataDirectorySections[16];
HTREEITEM htiSectionHeader;

HANDLE hPEFile;
VOID vCreateMenu(HWND hwnd);
BOOL OpenFileWithDialogue(HWND hwnd);
HANDLE hOpenPEFile(HWND hwnd);
HTREEITEM AddItemToTree(HWND hwndTV, string sItem, HTREEITEM hParent, BOOL bIncorrectElement = FALSE);

LONG GetLONGFromPEFile(HANDLE hPEFile, BOOL ReadFromCurrentPose = TRUE, LONG lDistanceToMove = 0, PLONG lpDistanceToMoveHigh = NULL);
string GetUTF8DWORDLONGFromPEFile(HANDLE hPEFile, BOOL ReadFromCurrentPose = TRUE, LONG lDistanceToMove = 0, PLONG lpDistanceToMoveHigh = NULL);
string GetStringFromLONG(LONG lData, BOOL bToHex = FALSE, BOOL bWriteWith0x = FALSE);
DWORD GetDWORDFromPEFile(HANDLE hPEFile, BOOL bReadFromCurrentPose = TRUE, LONG lDistanceToMove = 0, PLONG lpDistanceToMoveHigh = NULL);
WORD GetWORDFromPEFile(HANDLE hPEFile, BOOL bReadFromCurrentPose = TRUE, LONG lDistanceToMove = 0, PLONG lpDistanceToMoveHigh = NULL);
string GetStringFromDWORD(DWORD lData, BOOL bToHex = FALSE, BOOL bWriteWith0x = FALSE);
string GetStringFromDWORDHexAndDec(DWORD lData);
string GetStringFromWORD(WORD wData, BOOL bToHex = FALSE, BOOL bWriteWith0x = FALSE);
string GetStringFromWORDHexAndDec(WORD lData);
BYTE GetBYTEFromPEFile(HANDLE hPEFile, BOOL ReadFromCurrentPose = TRUE, LONG lDistanceToMove = 0, PLONG lpDistanceToMoveHigh = NULL);
string GetUTF8FromBYTE(BYTE byData);
string GetStringFromBYTE(BYTE BData, BOOL bToHex = FALSE, BOOL bWriteWith0x = FALSE);
//ULONGLONG GetULONGLONGFromPEFile(HANDLE hPEFile, BOOL bReadFromCurrentPose = TRUE, LONG lDistanceToMove = 0, PLONG lpDistanceToMoveHigh = NULL);
//string GetStringFromULONGLONG(ULONGLONG ullData, BOOL bToHex = FALSE, BOOL bWriteWith0x = FALSE);
ATOM RegisterCodeWndClass(HINSTANCE hInstance);
void CreateCodeButton(HINSTANCE hInstance, HWND hWndParent, int x, int y, int nWidth, int nHeight, string sTitle, LONG lBegOfCode, LONG lEndOfCode);
BOOL InitCodeWnd(HINSTANCE hInstance, size_t unIndexOfButton);
//BOOL InitCodeWnd(HINSTANCE hInstance, HWND* hWnd, unsigned int unIndexOfButton);
//BOOL InitCodeWnd(HINSTANCE hInstance, HWND* hWnd, LPCTSTR lpWindowName, LONG lBegOfCode, LONG lEndOfCode);
LRESULT CodeWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
VOID DestroyCodeWindowsAndButtons();
VOID AddItemToTable(HWND hWnd, string sItem, int nLine, int nColumn);
BOOL bIsPowerOfTwo(int nData);
BOOL OpenPage(HWND hWnd, LONG dwPage = 0);
string GetUTF8DWORDFromPEFile(HANDLE hPEFile, BOOL ReadFromCurrentPose = TRUE, LONG lDistanceToMove = 0, PLONG lpDistanceToMoveHigh = NULL);
string GetUTF8WORDFromPEFile(HANDLE hPEFile, BOOL ReadFromCurrentPose = TRUE, LONG lDistanceToMove = 0, PLONG lpDistanceToMoveHigh = NULL);
//HTREEITEM GetDataFromPEFile(HANDLE hPEFile, BOOL bReadFromCurrentPose, LONG lDistanceToMove, DWORD nNumberOfBytesToRead, HWND hwndTV, string sLabel, HTREEITEM hParent);
//HTREEITEM GetLONGFromPEFile(HANDLE hPEFile, BOOL bToHex, BOOL ReadFromCurrentPose, LONG lDistanceToMove, HWND hwndTV, string sLabel, HTREEITEM hParent, BOOL bUseBuffer = FALSE, LONG* plBuffer = nullptr);
//HTREEITEM GetHexWORDFromPEFile(HANDLE hPEFile, BOOL bReadFromCurrentPose, LONG lDistanceToMove, HWND hwndTV, string sLabel, HTREEITEM hParent, BOOL bUseBuffer = FALSE, char* psBuffer = nullptr);

const string szDOSStubCodeTitle = "DOS stub code";     
//HWND hDOSStubCodeWnd;