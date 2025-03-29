# PDF Watson - Security Inspector for PDFs

En Español: [![es](https://img.shields.io/badge/lang-es-yellow.svg)](README.es.MD)

PDF Watson is a minimalist tool developed in Python designed to scan PDF files for malicious code. The tool extracts metadata from the file and searches for common patterns associated with malicious codes, potentially harmful JavaScript, and dangerous embedded files.

## - IMPORTANT NOTE -
This is a proof of concept and should be used with caution at your own risk and always in controlled environments. This software has no guarantee or responsibility.

## Table of Contents

1. [PDF Watson - Security Inspector for PDFs](#pdf-watson---security-inspector-for-pdfs)
2. [Important Note](#--important-note--)
3. [Features](#features)
4. [Requirements](#requirements)
5. [Installation](#installation)
6. [Basic Usage](#basic-usage)
   - [Scan PDF](#scan-pdf)
   - [Scan Directory](#scan-directory)
7. [Results](#results)
8. [Common Issues](#common-issues)
   - [False Positives](#false-positives)
   - [PDF File Not Opening](#pdf-file-not-opening)
   - [Console Errors](#console-errors)
9. 
10. [License](#license)


## Features

- Metadata Extraction: Obtains information about the author, title, creation date, etc.
- Malicious Code Search: Detects common patterns in JavaScript and other elements that may indicate malicious codes.
- Detection of Dangerous Embedded Files: Identifies embedded files within the PDF with potentially dangerous extensions.

For more details, see [**documentation.en.md**](documentation.en.md)

## Requirements

- Python 3.9 or higher
- Libraries:
    - PyPDF2
    - magic
    - Tkinter

You can install the necessary libraries with the following command:

```bash
pip install -r requirements.txt
```

## Installation
Clone this repository.

```bash
git clone https://github.com/tu_usuario/PDF-Watson.git
cd PDF-Watson
python -m venv watson_env
watson_env\Scripts\activate  # On Windows
# For macOS/Linux use: source watson_env/bin/activate
pip install -r requirements.txt
```
## Basic Usage

1. **Run the Script**:
    ```bash
    python PDF-Watson.py
    ```
   
2. **Graphical User Interface**:
   When you run the script, a window will open where you can select a PDF file or a directory to perform an inspection.

To select a file, click on "Scan PDF". If you want to inspect a directory containing PDFs for batch inspections, select "Scan Directory".

![alt text](/images/main.jpg "Main Screen")

Below the buttons are 4 tabs with the results.
- **Summary**: Displays a summary of the inspection.
- **Metadata**: Shows the metadata.
- **Security Analysis**: Condenses relevant information about JavaScript code found.
- **Log**: Records the inspection history, operations, and execution errors stored in `pdf_watson.log`.

After performing an inspection, you can export the results to a .txt file.

## Results

- **File Metadata**: The extracted metadata from the PDF file will be displayed, such as author, title, creation date, etc.
- **Malicious Code Alerts**: If malicious patterns are detected in the JavaScript content, corresponding alerts will be shown.
- **Dangerous Embedded Files**: Embedded files within the PDF that may be dangerous will be identified, and alerts will be generated if necessary.
- **Log**: Documents the inspections performed, operations, and execution errors.

## Know Issues

### False Positives
If the document in question is related to programming, it may identify plain text code as malicious.

### PDF File Not Opening
If the file does not open correctly, make sure:
- Verify the file path.
- You have permissions to read the file.

### Console Errors
If you encounter errors while running the script, check the `pdf_watson.log` file for more detailed information about the error.

## To-Do List

- [ ] Improve the GUI
- [ ] Add the ability to ignore plain text to avoid false positives
- [ ] Contextual JavaScript code viewer
- [ ] Incorporate techniques learned from https://blog.didierstevens.com/


## License

This project is licensed under the GNU General Public License.