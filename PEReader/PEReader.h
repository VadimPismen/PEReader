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

const string s_MZ = "MZ";
const string s_DOStitle = "DOS title:";
const string s_DOSe_magic = "e_magic = ";
const string s_DOSe_lfanew = "e_lfanew = ";
const string s_PEtitle = "PE title:";
const string s_PESignature = "Signature = ";

HWND hPEStruct;
HTREEITEM htiDOStitle;
HTREEITEM htiDOSe_magic;
HTREEITEM htiDOSe_lfanew;
HTREEITEM htiPEtitle;
HTREEITEM htiPESignature;

void vCreateMenu(HWND hwnd);
HANDLE hOpenPEFile(HWND hwnd);
HTREEITEM AddItemToTree(HWND hwndTV, string lpszItem, HTREEITEM hParent);
HTREEITEM vGetDataFromPEFile(HANDLE PEFile, BOOL ReadFromCurrentPose, LONG lDistanceToMove, DWORD nNumberOfBytesToRead, HWND hwndTV, string label, HTREEITEM hParent);
HTREEITEM vGetLONGFromPEFile(HANDLE PEFile, BOOL tohex, BOOL ReadFromCurrentPose, LONG lDistanceToMove, HWND hwndTV, string label, HTREEITEM hParent, BOOL usebuffer = false, LONG* Buffer = NULL);
HTREEITEM vGetHexWORDFromPEFile(HANDLE PEFile, BOOL ReadFromCurrentPose, LONG lDistanceToMove, HWND hwndTV, string label, HTREEITEM hParent, BOOL usebuffer = false, char* Buffer = NULL);