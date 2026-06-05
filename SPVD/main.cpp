
#include <iostream>
#include <Windows.h>
#include <vector>
#include <filesystem>
#include <winnt.h>
#include <string>
#include <fstream>
#include "utils.h"
#include "Definiton.h"
#include <wintrust.h>
#include <softpub.h>
#include <thread>




#include <mutex>
std::mutex mtx;

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "Version.lib")

using namespace std;

int VulnerableFunctionCount = 0;
int ScannedFileCount = 0;
vector<DriverInfo> vDriverList_INFO;
vector<DriverInfo> vDriverList_Display;

// ================= FILE HANDLING =================

bool ReadFileToMemory(const std::filesystem::path& filePath, BYTE*& buffer, DWORD& fileSize)
{
    HANDLE hFile = CreateFileA(filePath.string().c_str(),
        GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE)
        return false;

    fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0)
    {
        CloseHandle(hFile);
        return false;
    }

    buffer = new BYTE[fileSize];
    DWORD bytesRead = 0;

    if (!ReadFile(hFile, buffer, fileSize, &bytesRead, NULL))
    {
        CloseHandle(hFile);
        delete[] buffer;
        return false;
    }

    CloseHandle(hFile);
    return true;
}

// ================= PE VALIDATION =================

bool IsValidPE(BYTE* buffer)
{
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)buffer;

    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    IMAGE_NT_HEADERS* ntHeader =
        reinterpret_cast<IMAGE_NT_HEADERS*>(buffer + dosHeader->e_lfanew);

    return (ntHeader->Signature == IMAGE_NT_SIGNATURE);
}



// ================= DRIVER INFO =================

void ProcessDriver(const filesystem::path& filePath, ofstream& logFile,
    int totalRisk,
    const string& foundList,
	int vulnerabilityScore,
    string productName)
{
    if (foundList.empty())
        return;

    DriverInfo driver;
    driver.name = filePath.filename().string();
    driver.path = filePath.string();
    driver.riskLevel = totalRisk;
    driver.listOfVulnerableFonction = foundList;
	driver.vulnerabilityScore = vulnerabilityScore;
    driver.productName = productName;

    vDriverList_INFO.push_back(driver);
    VulnerableFunctionCount++;

    logFile << "File: " << driver.name
        << " | Risk level: " << totalRisk
        << " | Vulnerability score: " << vulnerabilityScore << endl;
}

// ================= MAIN SCAN FUNCTION =================
bool IsFileSigned(const std::wstring& filePath)
{
    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = filePath.c_str();
    WINTRUST_DATA winTrustData = {};
    winTrustData.cbStruct = sizeof(WINTRUST_DATA);
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.pFile = &fileInfo;

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    LONG status = WinVerifyTrust(
        NULL,
        &policyGUID,
        &winTrustData
    );

    return (status == ERROR_SUCCESS);
}


std::string GetProductName(const std::wstring& filePath)
{
    DWORD handle = 0;

    DWORD size = GetFileVersionInfoSizeW(filePath.c_str(), &handle);
    if (size == 0)
        return "";

    std::vector<BYTE> buffer(size);

    if (!GetFileVersionInfoW(filePath.c_str(), 0, size, buffer.data()))
        return "";

    VS_FIXEDFILEINFO* fileInfo = nullptr;
    UINT len = 0;

    // Get language + codepage
    struct LANGANDCODEPAGE
    {
        WORD wLanguage;
        WORD wCodePage;
    };

    LANGANDCODEPAGE* translate;

    if (!VerQueryValueW(buffer.data(),
        L"\\VarFileInfo\\Translation",
        (LPVOID*)&translate,
        &len))
        return "";

    // Build query path
    wchar_t subBlock[50];
    swprintf_s(subBlock, 50,
        L"\\StringFileInfo\\%04x%04x\\ProductName",
        translate[0].wLanguage,
        translate[0].wCodePage);

    LPWSTR productName = nullptr;

    if (VerQueryValueW(buffer.data(),
        subBlock,
        (LPVOID*)&productName,
        &len))
    {
        // convert wide → string
        std::wstring ws(productName);
        return std::string(ws.begin(), ws.end());
    }

    return "";
}


/////////////////////////////////////////////////////////////////////////


void ScanSystemFile(const filesystem::path& filePath, ofstream& logFile)
{
    BYTE* buffer = nullptr;
    DWORD fileSize = 0;

    if (!ReadFileToMemory(filePath, buffer, fileSize))
        return;

    if (!IsValidPE(buffer))
    {
        delete[] buffer;
        return;
    }

    string binaryData(reinterpret_cast<char*>(buffer), fileSize);

    string foundList;
    int totalRisk = 0;
	int vulnerabilityScore = 0;
	bool isSigned = IsFileSigned(filePath.wstring());
	string productName = GetProductName(filePath);

    if (productName.find("Microsoft") != std::string::npos)
    {
        return;
    }

	if (productName.empty())
		productName = "Unknown";

    if (!isSigned)
       return;
     
	// Check for risk functions and calculate risk level and vulnerability score
    for (const auto& func : listOfFonctionScan)
    {
        if (binaryData.find(func) != string::npos)
        {
            foundList += func + ", ";

            totalRisk += RiskScores[func];

            if (VulnerabilityScores.find(func) != VulnerabilityScores.end())
            {
                vulnerabilityScore += VulnerabilityScores[func];
            }

        }
    }
	//Check for vulnerable functions
	ProcessDriver(filePath, logFile, totalRisk, foundList, vulnerabilityScore, productName);

    delete[] buffer;
}

// ================= DIRECTORY SCAN =================

void ScanDirectory(const string& rootPath, ofstream& logFile)
{
    namespace fs = std::filesystem;

    try
    {
        fs::recursive_directory_iterator it(
            rootPath,
            fs::directory_options::skip_permission_denied);
        fs::recursive_directory_iterator end;

        while (it != end)
        {
            try
            {
                const fs::directory_entry& entry = *it;

                if (entry.is_regular_file())
                {
                    auto path = entry.path();

                    if (path.extension() == ".sys")
                    {
                        ScanSystemFile(path, logFile);
                    }
                }

                ScannedFileCount++;

                cout << "Scanned files: " << ScannedFileCount
                    << " | Vulnerable files: " << VulnerableFunctionCount
                    << "\r" << flush;
            }
            catch (const fs::filesystem_error&)
            {
                // Skip problematic file
            }

            ++it;
        }
    }
    catch (const fs::filesystem_error& e)
    {
        cerr << "Filesystem error: " << e.what() << endl;
    }
}


// ================= SORTING =================

void SortDriversByRisk()
{
    vDriverList_Display = vDriverList_INFO; 

    sort(vDriverList_Display.begin(), vDriverList_Display.end(),
        [](const DriverInfo& a, const DriverInfo& b)
        {
            return a.riskLevel > b.riskLevel; // descending
        });
}


void sortDriversByVulnerabilityScore()
{
    vDriverList_Display = vDriverList_INFO; // copy

    sort(vDriverList_Display.begin(), vDriverList_Display.end(),
        [](const DriverInfo& a, const DriverInfo& b)
        {
            return a.vulnerabilityScore > b.vulnerabilityScore; // descending
        });
}

// ================= DISPLAY =================
void Display()
{
    clear();
	int choiceSort = 0; 

	cout << "choice sort by: \n1. Risk level\n2. Vulnerability score\nChoice: ";
	cin >> choiceSort;
    if (choiceSort == 1)
     SortDriversByRisk();
	else if (choiceSort == 2)
	sortDriversByVulnerabilityScore();

    int displayNumber = vDriverList_Display.size();
    for (int i = 0; i < min(displayNumber, (int)vDriverList_Display.size()); i++)
    {
        cout << "Driver: " << vDriverList_Display[i].name
            << " | Risk level: " << vDriverList_Display[i].riskLevel
            << " | Vulnerability score: " << vDriverList_Display[i].vulnerabilityScore
            << " | Product name: " << vDriverList_Display[i].productName << endl;
    }
}

// ================= MAIN =================

int main()
{
    string path;
    cout << "SPVD - System process vulnerability Detection\n";
    cout << "Files directory: ";
    cin >> path;

    ofstream logFile("SPVD_Report.txt", ios::out | ios::trunc);

    if (!logFile.is_open())
    {
        cout << "FAILED TO CREATE LOG FILE\n";
        return 1;
    }

    ScanDirectory(path, logFile);

    logFile.close();
    Display();

    while (true) {}
    return 0;
}
