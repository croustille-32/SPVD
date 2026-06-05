# SPVD
SPVD — System Process Vulnerability Detection
Overview
SPVD is a C++ application for Windows designed to scan system driver files (.sys) and identify potential vulnerabilities based on the presence of known risky functions in binary data.
The program recursively scans a user-specified directory, analyzes each eligible file, and produces a report listing files that may present security risks.

## Features

Recursive directory scanning
Detection and analysis of .sys files
Binary-level inspection of file contents
Identification of known vulnerable function signatures
Risk scoring based on detected functions
Console-based progress tracking
Report generation to a text file


### How It Works
The user provides a directory path.
The program traverses all subdirectories.
Each .sys file is opened and read into memory.
The file is validated as a Portable Executable (PE) using DOS and NT headers.
The binary content is searched for known function names defined in the project.
A risk score is calculated based on detected functions.
Results are written to SPVD_Report.txt.


## Requirements

Windows operating system
Visual Studio (2019 or later)
C++17 or later (for std::filesystem)


## Build and Run


Open the solution file:
SPVD.sln



Build the project using Visual Studio.


Run the executable.


Enter a directory path when prompted:
Files directory: C:\Windows\System32\drivers




## Output
Console
The console displays real-time progress:
Scanned files: X | Vulnerable files: Y

### Report File
Results are written to:
SPVD_Report.txt

### Example:
File: example.sys Risk level: 8
File: driver.sys Risk level: 12


## Limitations

Detection is based on string matching within binary data
Results may include false positives
Does not confirm actual exploitability
Large directories may result in longer scan times


## Security Considerations
This project does not include any credentials, secrets, or sensitive data. Users should ensure that no sensitive information is introduced when modifying or extending the code.

## Future Improvements
Reduction of false positives
Multi-threaded scanning
Graphical user interface


## Author
Elirock

## License
This project is open-source and available for modification and distribution.
