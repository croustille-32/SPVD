#include <iostream> 
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <math.h>
#include <filesystem>
#include <winnt.h>
#include <map>
#include <string>
#include <fstream>
#include "Definiton.h"
using namespace std;

int VulnerableFunctionCount = 0;
int ScannedFileCount = 0;

void clear() {
    COORD topLeft = { 0, 0 };
    HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO screen;
    DWORD written;

    GetConsoleScreenBufferInfo(console, &screen);
    FillConsoleOutputCharacterA(
        console, ' ', screen.dwSize.X * screen.dwSize.Y, topLeft, &written
    );
    FillConsoleOutputAttribute(
        console, FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_BLUE,
        screen.dwSize.X * screen.dwSize.Y, topLeft, &written
    );
    SetConsoleCursorPosition(console, topLeft);
}
int scanSystemFile(const std::filesystem::path& filePath, ofstream& logFile)
{
	// 0=Error, 1=Vulnerable, 2=Not Vulnerable
	int suspicious = 0;
    

	HANDLE hFile = CreateFileA(filePath.string().c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		cerr << "Failed to open file: " << filePath << endl;
		return 0;
	}

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0)
    {
        CloseHandle(hFile);
        return 0;
    }

	BYTE* buffer = new BYTE[fileSize];
	DWORD bytesRead = 0;
	if (!ReadFile(hFile, buffer, fileSize, &bytesRead, NULL))
	{
		cerr << "Failed to read file: " << filePath << endl;
		CloseHandle(hFile);
		delete[] buffer;
		return 0;
	}
    CloseHandle(hFile);


	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)buffer;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        delete[] buffer;
        return 0;
    }


    IMAGE_NT_HEADERS* ntHeader =
        reinterpret_cast<IMAGE_NT_HEADERS*>(
            buffer + dosHeader->e_lfanew);

    if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        delete[] buffer;
        return 0;
    }


    std::string binaryData(
        reinterpret_cast<char*>(buffer),
        fileSize
    );


    string FonctionFoundList = "";
    //SCAN STARTING
    int totalRisk = 0;
	for (int i = 0; i < listOfFonctionScan.size(); i++)
	{
		 const string FonctionToScan = listOfFonctionScan[i];
        

         if (binaryData.find(FonctionToScan)
             != std::string::npos)
         {
			 // If the function is found, add it to the list of found functions
			 FonctionFoundList += FonctionToScan + ", ";
             //Risk calculation

             totalRisk += vulnerabilityScores[FonctionToScan];
             

         }
	}

	if (FonctionFoundList != "")
	{
		VulnerableFunctionCount++;
		logFile << "File: " << filePath.filename() << "Risk level:" << totalRisk << endl;
	}

	// Clean up
	delete[] buffer;
	return suspicious; // Return true if the file is safe, false if a vulnerability is detected
}

int main()
{
	string path;
	cout << "SPVD - System process vulnerability Detection" << endl;
	cout << "Files directory: "; cin >> path;

	// Iterate through the directory and its subdirectories

    std::filesystem::recursive_directory_iterator iterator(path,std::filesystem::directory_options::skip_permission_denied);
    std::filesystem::recursive_directory_iterator end;
	// Loop through the directory entries

	// create a .txt file to log the results
	// if the .txt already exists, delete it
    ofstream logFile("SPVD_Report.txt", ios::out | ios::trunc);
    if (!logFile.is_open())
    {
        cout << "FAILED TO CREATE LOG FILE" << endl;
        return 1;
    }

    while (iterator != end)
    {
        // Get the current directory entry
        std::filesystem::directory_entry entry = *iterator;

        if (entry.is_regular_file())
        {
            std::filesystem::path path = entry.path();

            if (path.extension() == ".sys")
            {
			   scanSystemFile(path, logFile);
               
            }
        }

		ScannedFileCount++;
        ++iterator;
        cout << "Scanned files: "<< ScannedFileCount<< " | Vulnerable files: "<< VulnerableFunctionCount<< "\r" << flush;

  
    }

    logFile.close();
	return 0;
}







