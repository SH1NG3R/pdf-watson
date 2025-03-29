# Documentation of PDF Watson

En Español: [![es](https://img.shields.io/badge/lang-es-yellow.svg)](documentacion.es.md)

PDF Watson is a tool developed in Python that allows you to scan PDF files for potential threats.

## Table of Contents

1. [Documentation of PDF Watson](#documentation-of-pdf-watson)
2. [Code Structure](#code-structure)
   - [Metadata Class](#metadata-class)
   - [PDFWatson Class](#pdfwatson-class)
3. [Auxiliary Functions](#auxiliary-functions)
4. [Malicious Patterns](#malicious-patterns)
5. [Main Flow](#main-flow)
6. [Error Logging](#error-logging)

## Code Structure

The code is organized into two main classes: `Metadata` and `PDFWatson`. Additionally, there are several auxiliary functions to perform specific tasks.

### Metadata Class
This class is responsible for storing the metadata of the PDF. The attributes include information about the author, title, creation date, etc.

### PDFWatson Class
This is the main class that handles security analysis processes and metadata extraction. The class includes methods for:
- **scan_pdf_javascript**: Searches for potentially malicious JavaScript in the file.
- **scan_embedded_files**: Detects embedded files within the PDF that could be dangerous.

## Auxiliary Functions
In addition to the classes, there are auxiliary functions such as `extract_metadata` that are responsible for extracting information from the PDF file.

### Malicious Patterns
PDF Watson uses a series of regular expression patterns to identify potential threats in JavaScript content and other elements of the PDF. These patterns are listed in the variable `malicious_patterns`.

## Main Flow

1. **Metadata Extraction**: Information about the PDF file is extracted, such as author, title, etc.
2. **Malicious Code Search**: Known malicious code patterns are scanned in the JavaScript content of the file.
3. **Detection of Dangerous Embedded Files**: Embedded files within the PDF that could be dangerous are identified.

## Error Logging
All errors and exceptions are logged in a file called `pdf_watson.log` for subsequent analysis.

---
