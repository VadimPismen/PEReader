#pragma once

#include "resource.h"
#include <string>
#include <commdlg.h>
#include <CommCtrl.h>

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

#define IDC_OPENDOSSTUB			200

HWND hPEFileName;
HWND hPEStruct;
HTREEITEM htiDOS;
HTREEITEM htiDOSe_magic;
HTREEITEM htiDOSe_lfanew;
HTREEITEM htiDOSstub;
HTREEITEM htiPE;
HTREEITEM htiPESignature;

void vCreateMenu(HWND hwnd);
HANDLE hOpenPEFile(HWND hwnd);
HTREEITEM AddItemToTree(HWND hwndTV, string sItem, HTREEITEM hParent, BOOL bIncorrectElement = FALSE);

LONG GetLONGFromPEFile(HANDLE hPEFile, BOOL ReadFromCurrentPose = TRUE, LONG lDistanceToMove = 0, PLONG lpDistanceToMoveHigh = NULL);
string GetStringFromLONG(LONG lData, BOOL bToHex = FALSE);
DWORD GetDWORDFromPEFile(HANDLE hPEFile, BOOL bReadFromCurrentPose = TRUE, LONG lDistanceToMove = 0, PLONG lpDistanceToMoveHigh = NULL);
string GetStringFromDWORD(DWORD lData, BOOL bToHex = FALSE);
string GetUTF8DWORDFromPEFile(HANDLE hPEFile, BOOL ReadFromCurrentPose = TRUE, LONG lDistanceToMove = 0, PLONG lpDistanceToMoveHigh = NULL);
string GetUTF8WORDFromPEFile(HANDLE hPEFile, BOOL ReadFromCurrentPose = TRUE, LONG lDistanceToMove = 0, PLONG lpDistanceToMoveHigh = NULL);
//HTREEITEM GetDataFromPEFile(HANDLE hPEFile, BOOL bReadFromCurrentPose, LONG lDistanceToMove, DWORD nNumberOfBytesToRead, HWND hwndTV, string sLabel, HTREEITEM hParent);
//HTREEITEM GetLONGFromPEFile(HANDLE hPEFile, BOOL bToHex, BOOL ReadFromCurrentPose, LONG lDistanceToMove, HWND hwndTV, string sLabel, HTREEITEM hParent, BOOL bUseBuffer = FALSE, LONG* plBuffer = nullptr);
//HTREEITEM GetHexWORDFromPEFile(HANDLE hPEFile, BOOL bReadFromCurrentPose, LONG lDistanceToMove, HWND hwndTV, string sLabel, HTREEITEM hParent, BOOL bUseBuffer = FALSE, char* psBuffer = nullptr);