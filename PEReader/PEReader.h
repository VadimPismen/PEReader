#pragma once

#include "resource.h"
#include <string>
#include <commdlg.h>
#include <CommCtrl.h>
#include <ctime>

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
const string sOPTIONALHEADERDATADIRECTORYVIRTUALADDRESS = "VirtualAddress = ";
const string sOPTIONALHEADERDATADIRECTORYSIZE = "Size = ";


LONG lAddressOfPE;

#define IDC_OPENDOSSTUB			200

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
HTREEITEM htiOptionalHeaderDataDirectoryVirtualAddress;
HTREEITEM htiOptionalHeaderDataDirectorySize;

HANDLE hPEFile;
VOID vCreateMenu(HWND hwnd);
BOOL OpenFileWithDialogue(HWND hwnd);
HANDLE hOpenPEFile(HWND hwnd);
HTREEITEM AddItemToTree(HWND hwndTV, string sItem, HTREEITEM hParent, BOOL bIncorrectElement = FALSE);

LONG GetLONGFromPEFile(HANDLE hPEFile, BOOL ReadFromCurrentPose = TRUE, LONG lDistanceToMove = 0, PLONG lpDistanceToMoveHigh = NULL);
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
BOOL InitCodeWnd(HINSTANCE hInstance, HWND* hWnd, LPCTSTR lpWindowName, LONG lBegOfCode, LONG lEndOfCode);
LRESULT CodeWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
VOID DestroyCodeWindows();
VOID AddItemToTable(HWND hWnd, string sItem, int nLine, int nColumn);
BOOL bIsPowerOfTwo(int nData);
string GetUTF8DWORDFromPEFile(HANDLE hPEFile, BOOL ReadFromCurrentPose = TRUE, LONG lDistanceToMove = 0, PLONG lpDistanceToMoveHigh = NULL);
string GetUTF8WORDFromPEFile(HANDLE hPEFile, BOOL ReadFromCurrentPose = TRUE, LONG lDistanceToMove = 0, PLONG lpDistanceToMoveHigh = NULL);
//HTREEITEM GetDataFromPEFile(HANDLE hPEFile, BOOL bReadFromCurrentPose, LONG lDistanceToMove, DWORD nNumberOfBytesToRead, HWND hwndTV, string sLabel, HTREEITEM hParent);
//HTREEITEM GetLONGFromPEFile(HANDLE hPEFile, BOOL bToHex, BOOL ReadFromCurrentPose, LONG lDistanceToMove, HWND hwndTV, string sLabel, HTREEITEM hParent, BOOL bUseBuffer = FALSE, LONG* plBuffer = nullptr);
//HTREEITEM GetHexWORDFromPEFile(HANDLE hPEFile, BOOL bReadFromCurrentPose, LONG lDistanceToMove, HWND hwndTV, string sLabel, HTREEITEM hParent, BOOL bUseBuffer = FALSE, char* psBuffer = nullptr);

const string szDOSStubCodeTitle = "DOS stub code";
const string szCodeWndClass = "CODEWND";         
HWND hDOSStubCodeWnd;