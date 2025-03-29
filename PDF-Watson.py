import os
import re
import base64
import PyPDF2
import magic
import tkinter as tk
from tkinter import filedialog, scrolledtext, ttk, messagebox
import traceback
from datetime import datetime
import logging

#Esta es una prueba de concepto y debe ser usada con precaucion,
# bajo su propio riesgo y siempre en entornos controlados.
# Este programa no posee ninguna garantia ni responsabilidad.

#This is a proof of concept and should be used with caution 
# at your own risk and always in controlled environments.
# This software has no guarantee or responsibility.


# Log
logging.basicConfig(
    filename='pdf_watson.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s: %(message)s'
)

class Metadata:
    """Class to store PDF metadata"""
    def __init__(self):
        self.author = ""
        self.title = ""
        self.subject = ""
        self.creator = ""
        self.producer = ""
        self.creation_date = ""
        self.modification_date = ""
        self.keywords = ""
        self.page_count = 0
        self.file_size = 0
        self.file_path = ""

class PDFWatson:
    """Main PDF analysis engine combining security scanning and metadata extraction"""
    def __init__(self):
        # Malicious code patterns
        self.malicious_patterns = [
            # JavaScript suspicious patterns
            r'\b(eval|exec|system|cmd)\b',
            r'\b(Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\b',
            r'\b(document\.write|innerHTML)\b',
            
            # System commands
            r'\b(powershell|wget|curl|netcat|nc)\b',
            
            # Encoding/Decoding
            r'\b(base64_decode|fromCharCode)\b',
            
            # Code injection
            r'\{.*\}\..*\(.*\)',
            
            # Suspicious URLs
            r'http[s]?://\S+\.(exe|sh|ps1|bat|vbs)',
            
            # Remote execution
            r'\b(getURL|loadURL|launchURL)\b'
        ]
        
        # context-aware patterns with score weights
        self.context_patterns = {
            # Higher risk patterns (score 10)
            r'OpenAction\/JavaScript': 10,
            r'AA\/JavaScript': 10, 
            r'Launch\/': 10,
            r'SubmitForm': 8,
            
            # Medium risk patterns (score 5-7)
            r'(app\.)?eval': 7,
            r'(app\.)?execMenuItem': 6,
            r'shellcode': 7,
            r'this\.submitForm': 5,
            
            # Lower risk patterns (score 2-4)
            r'util\.printd': 3,
            r'util\.printf': 3,
            r'getAnnots': 2,
            r'getPageNthWord': 2,
            r'exportDataObject': 4
        }
        
        # JavaScript suspicious keywords
        self.js_suspicious_keywords = [
            'downloadAndExecute', 
            'system.exec', 
            'runtime.getRuntime', 
            'shell.execute',
            'launch',
            'exportdata',
            'shellcode',
            'spawnprocess',
            'escapeshell'
        ]
        
        # Dangerous embedded file extensions
        self.dangerous_extensions = [
            '.exe', '.bat', '.cmd', '.vbs', '.ps1', '.sh', 
            '.dll', '.scr', '.jar', '.hta', '.msi'
        ]

    def scan_pdf(self, pdf_path):
        """Main scanning function that combines all scans"""
        results = {
            'metadata': self.extract_metadata(pdf_path),
            'javascript': self.scan_pdf_javascript(pdf_path),
            'embedded_files': self.scan_embedded_files(pdf_path),
            'obfuscation': self.detect_obfuscation(pdf_path),
            'advanced_threats': self.scan_advanced_threats(pdf_path),
            'risk_score': 0
        }
        
        # Calculate risk score based on findings
        risk_score = 0
        #--
        risk_score += len(results['javascript']) * 3
        risk_score += len(results['embedded_files']) * 5
        risk_score += len(results['obfuscation']) * 4
        risk_score += len(results['advanced_threats']) * 6
        
        # Set final risk score
        results['risk_score'] = min(risk_score, 100)  # Cap at 100
        
        return results
    
    def extract_metadata(self, pdf_path):
        """Extract metadata from PDF"""
        metadata = Metadata()
        metadata.file_path = pdf_path
        
        try:
            # Get file size
            metadata.file_size = os.path.getsize(pdf_path) / 1024  # KB
            
            with open(pdf_path, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file)
                
                # Get page count
                metadata.page_count = len(pdf_reader.pages)
                
                # Extraer informacion
                if pdf_reader.metadata:
                    info = pdf_reader.metadata
                    metadata.author = info.get('/Author', '')
                    metadata.title = info.get('/Title', '')
                    metadata.subject = info.get('/Subject', '')
                    metadata.creator = info.get('/Creator', '')
                    metadata.producer = info.get('/Producer', '')
                    metadata.creation_date = info.get('/CreationDate', '')
                    metadata.modification_date = info.get('/ModDate', '')
                    metadata.keywords = info.get('/Keywords', '')
        
        except Exception as e:
            logging.error(f"Error extracting metadata: {e}")
            traceback.print_exc()
        
        return metadata
    
    def scan_pdf_javascript(self, pdf_path):
        """Scan PDF for malicious JavaScript"""
        findings = []
        
        try:
            with open(pdf_path, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file)
                
                # Check for JavaScript in document catalog
                root = pdf_reader.trailer.get('/Root', {})
                if isinstance(root, PyPDF2.generic.IndirectObject):
                    root = root.get_object()
                    
                if isinstance(root, dict) and '/OpenAction' in root:
                    action = root['/OpenAction']
                    if isinstance(action, PyPDF2.generic.IndirectObject):
                        action = action.get_object()
                        
                    if isinstance(action, dict) and '/JS' in action:
                        findings.append({
                            'location': 'Document OpenAction',
                            'type': 'JavaScript Auto-Execution',
                            'severity': 'High'
                        })
                # Scan each page for JavaScript
                for page_num, page in enumerate(pdf_reader.pages, 1):
                    # Extract text from page
                    page_text = page.extract_text() if page.extract_text() else ""
                    
                    # Look for JavaScript patterns
                    for pattern in self.malicious_patterns:
                        matches = re.findall(pattern, page_text, re.IGNORECASE)
                        if matches:
                            findings.append({
                                'page': page_num,
                                'type': 'Suspicious Pattern',
                                'pattern': pattern,
                                'matches': list(set(matches)),
                                'severity': 'Medium'
                            })
                    
                    # Look for JavaScript keywords
                    for keyword in self.js_suspicious_keywords:
                        if keyword.lower() in page_text.lower():
                            findings.append({
                                'page': page_num,
                                'type': 'Suspicious Keyword',
                                'keyword': keyword,
                                'severity': 'Medium'
                            })
                
                # Look for context-specific patterns with scoring
                pdf_content = ""
                for page in pdf_reader.pages:
                    if page.extract_text():
                        pdf_content += page.extract_text()
                
                for pattern, score in self.context_patterns.items():
                    if re.search(pattern, pdf_content, re.IGNORECASE):
                        findings.append({
                            'type': 'Context Pattern',
                            'pattern': pattern,
                            'risk_score': score,
                            'severity': 'High' if score >= 7 else 'Medium' if score >= 4 else 'Low'
                        })
        
        except Exception as e:
            logging.error(f"Error scanning JavaScript: {e}")
            traceback.print_exc()
        
        return findings
    
    def scan_embedded_files(self, pdf_path):
        """Detect dangerous embedded files"""
        dangerous_files = []
        
        try:
            with open(pdf_path, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file)
                
                # Check for embedded files in Names tree
                root = pdf_reader.trailer.get('/Root', {})
                if isinstance(root, PyPDF2.generic.IndirectObject):
                    root = root.get_object()
                    
                if isinstance(root, dict) and '/Names' in root:
                    names = root['/Names']
                    if isinstance(names, PyPDF2.generic.IndirectObject):
                        names = names.get_object()
                        
                    if isinstance(names, dict) and '/EmbeddedFiles' in names:
                        embedded_files = names['/EmbeddedFiles']
                        if isinstance(embedded_files, PyPDF2.generic.IndirectObject):
                            embedded_files = embedded_files.get_object()
                            
                        for obj in embedded_files.get('/Names', []):
                            if isinstance(obj, dict) and '/F' in obj:
                                filename = obj['/F']
                                
                                # Check for dangerous extensions
                                for ext in self.dangerous_extensions:
                                    if filename.lower().endswith(ext):
                                        dangerous_files.append({
                                            'filename': filename,
                                            'type': f'Dangerous embedded file ({ext})',
                                            'severity': 'High'
                                        })
        
        except Exception as e:
            logging.error(f"Error scanning embedded files: {e}")
            traceback.print_exc()
        
        return dangerous_files    
    def detect_obfuscation(self, pdf_path):
        """Detect obfuscation techniques"""
        obfuscation_signs = []
        
        try:
            with open(pdf_path, 'rb') as file:
                content = file.read()
                content_str = content.decode('latin-1', errors='ignore')
                
                # Check for excessive whitespace obfuscation
                if re.search(r'(\s{10,})', content_str):
                    obfuscation_signs.append({
                        'type': 'Excessive Whitespace',
                        'severity': 'Medium'
                    })
                
                # Check for hex-encoded strings
                hex_patterns = re.findall(r'\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}', content_str)
                if hex_patterns:
                    obfuscation_signs.append({
                        'type': 'Hex-Encoded Content',
                        'count': len(hex_patterns),
                        'severity': 'Medium'
                    })
                
                # Check for Base64 content
                base64_matches = re.findall(r'([A-Za-z0-9+/]{40,}={0,2})', content_str)
                for match in base64_matches[:10]:  # Limit to first 10 matches
                    try:
                        decoded = base64.b64decode(match)
                        # Check if decoded content seems malicious
                        decoded_str = decoded.decode('latin-1', errors='ignore')
                        for pattern in self.malicious_patterns:
                            if re.search(pattern, decoded_str, re.IGNORECASE):
                                obfuscation_signs.append({
                                    'type': 'Base64 Obfuscation',
                                    'decoded_contains': pattern,
                                    'severity': 'High'
                                })
                                break
                    except:
                        pass
        
        except Exception as e:
            logging.error(f"Error detecting obfuscation: {e}")
            traceback.print_exc()
        
        return obfuscation_signs
    

    def scan_advanced_threats(self, pdf_path):
        """Scan for advanced PDF threats"""
        advanced_threats = []
        
        try:
            with open(pdf_path, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file)
                
                # Check for AcroForm with JavaScript actions
                root = pdf_reader.trailer.get('/Root', {})
                if isinstance(root, PyPDF2.generic.IndirectObject):
                    root = root.get_object()
                    
                if isinstance(root, dict) and '/AcroForm' in root:
                    acroform = root['/AcroForm']
                    if isinstance(acroform, PyPDF2.generic.IndirectObject):
                        acroform = acroform.get_object()
                        
                    if isinstance(acroform, dict) and '/Fields' in acroform:
                        fields = acroform['/Fields']
                        for field in fields:
                            if isinstance(field, PyPDF2.generic.IndirectObject):
                                field = field.get_object()
                                
                            if isinstance(field, dict) and '/A' in field:
                                action = field['/A']
                                if isinstance(action, PyPDF2.generic.IndirectObject):
                                    action = action.get_object()
                                    
                                if isinstance(action, dict) and '/S' in action and action['/S'] == '/JavaScript':
                                    advanced_threats.append({
                                        'type': 'AcroForm JavaScript',
                                        'severity': 'High'
                                    })
                
                # Check for /AA (Additional Actions) entries
                if isinstance(root, dict) and '/AA' in root:
                    advanced_threats.append({
                        'type': 'Document Additional Actions',
                        'severity': 'High' 
                    })                
                # Check for /AA (Additional Actions) entries
                root = pdf_reader.trailer.get('/Root', {})
                if isinstance(root, PyPDF2.generic.IndirectObject):
                    root = root.get_object()
                    
                if isinstance(root, dict) and '/AA' in root:
                    advanced_threats.append({
                        'type': 'Document Additional Actions',
                        'severity': 'High' 
                    })
                
                # Check for unusual compression methods
                content_str = ""
                with open(pdf_path, 'rb') as f:
                    content_str = f.read().decode('latin-1', errors='ignore')
                
                if '/FlateDecode/ASCIIHexDecode' in content_str or '/FlateDecode/AHx' in content_str:
                    advanced_threats.append({
                        'type': 'Unusual Compression Chain',
                        'severity': 'Medium'
                    })
                
                # Check for suspicious /Type entries
                suspicious_types = ['/XFA', '/RichMedia', '/Movie', '/Sound', '/Screen']
                for sus_type in suspicious_types:
                    if sus_type in content_str:
                        advanced_threats.append({
                            'type': f'Suspicious Content Type: {sus_type}',
                            'severity': 'Medium'
                        })
        
        except Exception as e:
            logging.error(f"Error scanning advanced threats: {e}")
            traceback.print_exc()
        
        return advanced_threats

class PDFWatsonGUI:
    """GUI for PDF-Watson"""
    def __init__(self, root):
        self.root = root
        self.root.title("PDF-Watson")
        self.root.geometry("1000x700")
        
        # Initialize PDF analyzer
        self.analyzer = PDFWatson()
        
        # Create color scheme for dark theme
        self.colors = {
            'bg': '#1e1e2e',            # Background
            'fg': '#cdd6f4',            # Text color
            'accent': '#89b4fa',        # Accent color
            'warning': '#f9e2af',       # Warning color
            'danger': '#f38ba8',        # Danger color
            'success': '#a6e3a1',       # Success color
            'button': '#313244',        # Button background
            'button_hover': '#45475a',  # Button hover
            'frame': '#181825',         # Frame background
            'border': '#45475a'         # Border color
        }
        
        self.configure_theme()
        
        self.create_gui()
        
        self.current_file = None
        self.current_results = None
    
    def configure_theme(self):
        """Configure custom dark theme"""
        self.root.configure(bg=self.colors['bg'])
        
        style = ttk.Style()
        style.theme_use('default')
        
        style.configure('TButton', 
                        background=self.colors['button'],
                        foreground=self.colors['fg'],
                        borderwidth=1,
                        focusthickness=3,
                        focuscolor=self.colors['accent'])
        
        style.map('TButton',
                 background=[('active', self.colors['button_hover'])])
        
        style.configure('TFrame', background=self.colors['bg'])
        
        style.configure('TLabel', 
                        background=self.colors['bg'],
                        foreground=self.colors['fg'])
        
        style.configure('Heading.TLabel',
                       background=self.colors['bg'],
                       foreground=self.colors['accent'],
                       font=('Helvetica', 16, 'bold'))
        
        style.configure('Metadata.TLabel',
                       background=self.colors['frame'],
                       foreground=self.colors['fg'])
        
        style.configure('Low.TLabel',
                       background=self.colors['bg'],
                       foreground=self.colors['success'],
                       font=('Helvetica', 12, 'bold'))
        
        style.configure('Medium.TLabel',
                       background=self.colors['bg'],
                       foreground=self.colors['warning'],
                       font=('Helvetica', 12, 'bold'))
        
        style.configure('High.TLabel',
                       background=self.colors['bg'],
                       foreground=self.colors['danger'],
                       font=('Helvetica', 12, 'bold'))
    
    def create_gui(self):
        """Create the main GUI layout"""
        main_frame = ttk.Frame(self.root, style='TFrame')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        header_frame = ttk.Frame(main_frame, style='TFrame')
        header_frame.pack(fill=tk.X, pady=10)
        
        title_label = ttk.Label(header_frame, text="PDF-Watson", style='Heading.TLabel')
        title_label.pack(side=tk.TOP)
        
        button_frame = ttk.Frame(main_frame, style='TFrame')
        button_frame.pack(fill=tk.X, pady=10)
        
        self.scan_btn = ttk.Button(button_frame, text="Scan PDF", command=self.select_pdf)
        self.scan_btn.pack(side=tk.LEFT, padx=5)
        
        self.scan_dir_btn = ttk.Button(button_frame, text="Scan Directory", command=self.select_directory)
        self.scan_dir_btn.pack(side=tk.LEFT, padx=5)
        
        self.export_btn = ttk.Button(button_frame, text="Export Report", command=self.export_report)
        self.export_btn.pack(side=tk.LEFT, padx=5)
        
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.summary_frame = ttk.Frame(self.notebook, style='TFrame')
        self.notebook.add(self.summary_frame, text="Summary")
        
        self.create_summary_tab()
        
        self.metadata_frame = ttk.Frame(self.notebook, style='TFrame')
        self.notebook.add(self.metadata_frame, text="Metadata")
        
        self.create_metadata_tab()
        
        self.security_frame = ttk.Frame(self.notebook, style='TFrame')
        self.notebook.add(self.security_frame, text="Security Analysis")
        
        self.create_security_tab()
        
        self.log_frame = ttk.Frame(self.notebook, style='TFrame')
        self.notebook.add(self.log_frame, text="Log")
        self.create_log_tab()
        
        # Footer
        footer_frame = ttk.Frame(main_frame, style='TFrame')
        footer_frame.pack(fill=tk.X, pady=10)
        version_label = ttk.Label(footer_frame, text="PDF-Watson v0.1 [ALPHA]", style='TLabel')
        version_label.pack(side=tk.LEFT)
        author_label = ttk.Label(footer_frame, text="By SH1NG3R, Use at your own risk", style='TLabel')
        author_label.pack(side=tk.RIGHT)
    
    def create_summary_tab(self):
        """Create summary tab content"""
        # Risk score frame
        risk_frame = ttk.Frame(self.summary_frame, style='TFrame')
        risk_frame.pack(fill=tk.X, pady=10)
        
        self.risk_label = ttk.Label(risk_frame, text="Risk Score: N/A", style='TLabel')
        self.risk_label.pack(side=tk.LEFT, padx=10)
        
        self.risk_level = ttk.Label(risk_frame, text="Risk Level: N/A", style='TLabel')
        self.risk_level.pack(side=tk.LEFT, padx=10)
        
        # File info
        file_frame = ttk.Frame(self.summary_frame, style='TFrame')
        file_frame.pack(fill=tk.X, pady=5)
        
        self.file_label = ttk.Label(file_frame, text="File: No file selected", style='TLabel')
        self.file_label.pack(side=tk.LEFT, padx=10)
        
        # Create findings summary
        findings_frame = ttk.Frame(self.summary_frame, style='TFrame')
        findings_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Findings text area
        self.summary_text = scrolledtext.ScrolledText(findings_frame, wrap=tk.WORD, bg=self.colors['frame'], fg=self.colors['fg'])
        self.summary_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.summary_text.config(state=tk.DISABLED)
    
    def create_metadata_tab(self):
        """Create metadata tab content"""
        # Create a frame for metadata display
        metadata_content = ttk.Frame(self.metadata_frame, style='TFrame')
        metadata_content.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create metadata text area
        self.metadata_text = scrolledtext.ScrolledText(metadata_content, wrap=tk.WORD, bg=self.colors['frame'], fg=self.colors['fg'])
        self.metadata_text.pack(fill=tk.BOTH, expand=True)
        self.metadata_text.config(state=tk.DISABLED)
    
    def create_security_tab(self):
        """Create security analysis tab content"""
        security_content = ttk.Frame(self.security_frame, style='TFrame')
        security_content.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.security_text = scrolledtext.ScrolledText(security_content, wrap=tk.WORD, bg=self.colors['frame'], fg=self.colors['fg'])
        self.security_text.pack(fill=tk.BOTH, expand=True)
        self.security_text.config(state=tk.DISABLED)
    
    def create_log_tab(self):
        """Create log tab content"""
        # Create a frame for log display
        log_content = ttk.Frame(self.log_frame, style='TFrame')
        log_content.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.log_text = scrolledtext.ScrolledText(log_content, wrap=tk.WORD, bg=self.colors['frame'], fg=self.colors['fg'])
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.config(state=tk.DISABLED)
    
    def select_pdf(self):
        """Select and analyze a PDF file"""
        file_path = filedialog.askopenfilename(filetypes=[("PDF files", "*.pdf")])
        if not file_path:
            return
        
        self.current_file = file_path
        
        self.file_label.config(text=f"File: {os.path.basename(file_path)}")
        
        # Show analysis in progress
        self.show_status("Analyzing PDF file...")
        
        try:
            results = self.analyzer.scan_pdf(file_path)
            self.current_results = results
            self.update_ui_with_results(results)
            self.show_status("Analysis complete")
            
        except Exception as e:
            logging.error(f"Error analyzing PDF: {e}")
            messagebox.showerror("Error", f"Failed to analyze PDF: {str(e)}")
            traceback.print_exc()
    
    def select_directory(self):
        """Select and analyze all PDFs in a directory"""
        dir_path = filedialog.askdirectory()
        if not dir_path:
            return
        
        # Count PDF files
        pdf_files = [f for f in os.listdir(dir_path) if f.lower().endswith('.pdf')]
        
        if not pdf_files:
            messagebox.showinfo("Information", "No PDF files found in the selected directory.")
            return
        
        # Ask for confirmation
        confirm = messagebox.askyesno("Confirm Batch Analysis", 
                                      f"Found {len(pdf_files)} PDF files. Proceed with batch analysis?")
        if not confirm:
            return
        
        # Show analysis in progress
        self.show_status(f"Analyzing {len(pdf_files)} PDF files...")
        
        # Clear all text areas
        self.clear_all_text_areas()
        
        # Prepare report
        batch_report = f"Batch Analysis Report\n"
        batch_report += f"Directory: {dir_path}\n"
        batch_report += f"Files analyzed: {len(pdf_files)}\n"
        batch_report += f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        batch_report += "=" * 50 + "\n\n"
        
        high_risk_files = []
        medium_risk_files = []
        low_risk_files = []
        
        # Analyze each PDF
        for idx, pdf_file in enumerate(pdf_files):
            full_path = os.path.join(dir_path, pdf_file)
            self.show_status(f"Analyzing file {idx+1} of {len(pdf_files)}: {pdf_file}")
            
            try:
                # Analyze PDF
                results = self.analyzer.scan_pdf(full_path)
                
                # Add to appropriate risk category
                risk_score = results['risk_score']
                if risk_score >= 70:
                    high_risk_files.append((pdf_file, risk_score))
                elif risk_score >= 30:
                    medium_risk_files.append((pdf_file, risk_score))
                else:
                    low_risk_files.append((pdf_file, risk_score))
                
                # Add summary to report
                batch_report += f"File: {pdf_file}\n"
                batch_report += f"Risk Score: {risk_score}\n"
                
                # Count findings
                js_count = len(results['javascript'])
                embedded_count = len(results['embedded_files'])
                obfuscation_count = len(results['obfuscation'])
                advanced_count = len(results['advanced_threats'])
                
                batch_report += f"JavaScript Issues: {js_count}\n"
                batch_report += f"Embedded Files: {embedded_count}\n"
                batch_report += f"Obfuscation Techniques: {obfuscation_count}\n"
                batch_report += f"Advanced Threats: {advanced_count}\n"
                batch_report += "-" * 50 + "\n\n"
                
            except Exception as e:
                logging.error(f"Error analyzing {pdf_file}: {e}")
                batch_report += f"File: {pdf_file}\n"
                batch_report += f"Error: {str(e)}\n"
                batch_report += "-" * 50 + "\n\n"
        
        # Add risk summary
        batch_report += "Risk Summary\n"
        batch_report += "=" * 50 + "\n"
        batch_report += f"High Risk Files: {len(high_risk_files)}\n"
        for file, score in high_risk_files:
            batch_report += f"  - {file}: Score {score}\n"
        
        batch_report += f"\nMedium Risk Files: {len(medium_risk_files)}\n"
        for file, score in medium_risk_files:
            batch_report += f"  - {file}: Score {score}\n"
        
        batch_report += f"\nLow Risk Files: {len(low_risk_files)}\n"
        for file, score in low_risk_files:
            batch_report += f"  - {file}: Score {score}\n"
        
        # Display batch report
        self.security_text.config(state=tk.NORMAL)
        self.security_text.delete(1.0, tk.END)
        self.security_text.insert(tk.END, batch_report)
        self.security_text.config(state=tk.DISABLED)
        
        # Switch to security tab
        self.notebook.select(self.security_frame)
        
        # Show completed status
        self.show_status("Batch analysis complete")
        
        # Offer to save the report
        save = messagebox.askyesno("Save Report", "Would you like to save the batch analysis report?")
        if save:
            self.export_report(batch_report)
    
    def update_ui_with_results(self, results):
        """Update UI with analysis results"""
        # Clear all text areas
        self.clear_all_text_areas()
        
        # Update risk score
        risk_score = results['risk_score']
        self.risk_label.config(text=f"Risk Score: {risk_score}")
        
        # Set risk level based on score
        if risk_score >= 70:
            risk_level = "High"
            self.risk_level.config(text=f"Risk Level: {risk_level}", style='High.TLabel')
        elif risk_score >= 30:
            risk_level = "Medium"
            self.risk_level.config(text=f"Risk Level: {risk_level}", style='Medium.TLabel')
        else:
            risk_level = "Low"
            self.risk_level.config(text=f"Risk Level: {risk_level}", style='Low.TLabel')
        
        # Update summary tab
        self.summary_text.config(state=tk.NORMAL)
        self.summary_text.delete(1.0, tk.END)
        
        summary = f"PDF Security Analysis Summary\n"
        summary += "=" * 40 + "\n\n"
        
# Basic file info
        metadata = results['metadata']
        summary += f"File: {os.path.basename(metadata.file_path)}\n"
        summary += f"Size: {metadata.file_size:.2f} KB\n"
        summary += f"Pages: {metadata.page_count}\n\n"
        
        # Findings summary
        js_findings = results['javascript']
        embedded_files = results['embedded_files']
        obfuscation = results['obfuscation']
        advanced_threats = results['advanced_threats']
        
        summary += "Findings Summary:\n"
        summary += f"- JavaScript Issues: {len(js_findings)}\n"
        summary += f"- Dangerous Embedded Files: {len(embedded_files)}\n"
        summary += f"- Obfuscation Techniques: {len(obfuscation)}\n"
        summary += f"- Advanced Threats: {len(advanced_threats)}\n\n"
        
        # List high severity findings
        high_severity = []
        
        for finding in js_findings:
            if finding.get('severity') == 'High':
                high_severity.append(f"JavaScript: {finding.get('type')}")
        
        for file in embedded_files:
            if file.get('severity') == 'High':
                high_severity.append(f"Embedded File: {file.get('filename')}")
        
        for technique in obfuscation:
            if technique.get('severity') == 'High':
                high_severity.append(f"Obfuscation: {technique.get('type')}")
        
        for threat in advanced_threats:
            if threat.get('severity') == 'High':
                high_severity.append(f"Advanced Threat: {threat.get('type')}")
        
        if high_severity:
            summary += "High Severity Issues:\n"
            for issue in high_severity:
                summary += f"- {issue}\n"
        
        self.summary_text.insert(tk.END, summary)
        self.summary_text.config(state=tk.DISABLED)
        
        # Update metadata tab
        self.metadata_text.config(state=tk.NORMAL)
        self.metadata_text.delete(1.0, tk.END)
        
        metadata_text = "PDF Metadata\n"
        metadata_text += "=" * 30 + "\n\n"
        metadata_text += f"File: {metadata.file_path}\n"
        metadata_text += f"Size: {metadata.file_size:.2f} KB\n"
        metadata_text += f"Pages: {metadata.page_count}\n\n"
        metadata_text += f"Author: {metadata.author}\n"
        metadata_text += f"Title: {metadata.title}\n"
        metadata_text += f"Subject: {metadata.subject}\n"
        metadata_text += f"Creator: {metadata.creator}\n"
        metadata_text += f"Producer: {metadata.producer}\n"
        metadata_text += f"Creation Date: {metadata.creation_date}\n"
        metadata_text += f"Modification Date: {metadata.modification_date}\n"
        metadata_text += f"Keywords: {metadata.keywords}\n"
        
        self.metadata_text.insert(tk.END, metadata_text)
        self.metadata_text.config(state=tk.DISABLED)
        
        # Update security tab
        self.security_text.config(state=tk.NORMAL)
        self.security_text.delete(1.0, tk.END)
        
        security_text = "Security Analysis Details\n"
        security_text += "=" * 30 + "\n\n"
        
        # JavaScript findings
        if js_findings:
            security_text += "JavaScript Issues:\n"
            security_text += "-" * 20 + "\n"
            for idx, finding in enumerate(js_findings, 1):
                security_text += f"{idx}. {finding.get('type', 'Unknown Issue')}\n"
                if 'page' in finding:
                    security_text += f"   Page: {finding['page']}\n"
                if 'location' in finding:
                    security_text += f"   Location: {finding['location']}\n"
                if 'pattern' in finding:
                    security_text += f"   Pattern: {finding['pattern']}\n"
                if 'matches' in finding:
                    security_text += f"   Matches: {', '.join(finding['matches'])}\n"
                if 'keyword' in finding:
                    security_text += f"   Keyword: {finding['keyword']}\n"
                security_text += f"   Severity: {finding.get('severity', 'Unknown')}\n\n"
        else:
            security_text += "No JavaScript issues found.\n\n"
        
        # Embedded files
        if embedded_files:
            security_text += "Dangerous Embedded Files:\n"
            security_text += "-" * 20 + "\n"
            for idx, file in enumerate(embedded_files, 1):
                security_text += f"{idx}. {file.get('filename', 'Unknown File')}\n"
                security_text += f"   Type: {file.get('type', 'Unknown Type')}\n"
                security_text += f"   Severity: {file.get('severity', 'Unknown')}\n\n"
        else:
            security_text += "No dangerous embedded files found.\n\n"
        
        # Obfuscation techniques (i like that word)
        if obfuscation:
            security_text += "Obfuscation Techniques:\n"
            security_text += "-" * 20 + "\n"
            for idx, technique in enumerate(obfuscation, 1):
                security_text += f"{idx}. {technique.get('type', 'Unknown Technique')}\n"
                if 'count' in technique:
                    security_text += f"   Count: {technique['count']}\n"
                if 'decoded_contains' in technique:
                    security_text += f"   Decoded Contains: {technique['decoded_contains']}\n"
                security_text += f"   Severity: {technique.get('severity', 'Unknown')}\n\n"
        else:
            security_text += "No obfuscation techniques found.\n\n"
        
        # Advanced threats
        if advanced_threats:
            security_text += "Advanced Threats:\n"
            security_text += "-" * 20 + "\n"
            for idx, threat in enumerate(advanced_threats, 1):
                security_text += f"{idx}. {threat.get('type', 'Unknown Threat')}\n"
                security_text += f"   Severity: {threat.get('severity', 'Unknown')}\n\n"
        else:
            security_text += "No advanced threats found.\n\n"
        
        self.security_text.insert(tk.END, security_text)
        self.security_text.config(state=tk.DISABLED)
        
        # Update log
        self.update_log(f"Analysis completed for {os.path.basename(metadata.file_path)}")
        self.update_log(f"Risk Score: {risk_score} (Level: {risk_level})")
        self.update_log(f"Found {len(js_findings)} JavaScript issues, {len(embedded_files)} dangerous files, "
                        f"{len(obfuscation)} obfuscation techniques, and {len(advanced_threats)} advanced threats.")
    
    def export_report(self, content=None):
        """Export analysis report to a text file"""
        if not content and not self.current_results:
            messagebox.showinfo("Information", "No analysis results to export.")
            return
        
        # Direccion de guardado
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"pdf_watson_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )
        
        if not file_path:
            return
        
        try:
            with open(file_path, 'w') as file:
                if content:
                    file.write(content)
                else:
                    # Generate comprehensive report
                    results = self.current_results
                    report = "PDF-Watson Security Analysis Report\n"
                    report += "=" * 50 + "\n\n"
                    
                    # file info
                    metadata = results['metadata']
                    report += f"File: {metadata.file_path}\n"
                    report += f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                    report += f"Risk Score: {results['risk_score']}\n\n"
                    
                    # Metadata section
                    report += "Metadata\n"
                    report += "-" * 20 + "\n"
                    report += f"Size: {metadata.file_size:.2f} KB\n"
                    report += f"Pages: {metadata.page_count}\n"
                    report += f"Author: {metadata.author}\n"
                    report += f"Title: {metadata.title}\n"
                    report += f"Subject: {metadata.subject}\n"
                    report += f"Creator: {metadata.creator}\n"
                    report += f"Producer: {metadata.producer}\n"
                    report += f"Creation Date: {metadata.creation_date}\n"
                    report += f"Modification Date: {metadata.modification_date}\n"
                    report += f"Keywords: {metadata.keywords}\n\n"
                    
                    # Security findings
                    report += "Security Findings\n"
                    report += "=" * 50 + "\n\n"
                    
                    # Get security text from security tab
                    security_content = self.security_text.get(1.0, tk.END)
                    report += security_content
                    
                    file.write(report)
            
            messagebox.showinfo("Success", f"Report saved to {file_path}")
            self.update_log(f"Report exported to {file_path}")
            
        except Exception as e:
            logging.error(f"Error exporting report: {e}")
            messagebox.showerror("Error", f"Failed to export report: {str(e)}")
    
    def show_status(self, message):
        """Show status message in the log"""
        self.update_log(message)
        self.root.update_idletasks()
    
    def update_log(self, message):
        """Add message to log tab"""
        self.log_text.config(state=tk.NORMAL)
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)  # Scroll to end
        self.log_text.config(state=tk.DISABLED)
        
        logging.info(message)
    
    def clear_all_text_areas(self):
        """Clear all text areas"""
        for text_widget in [self.summary_text, self.metadata_text, self.security_text]:
            text_widget.config(state=tk.NORMAL)
            text_widget.delete(1.0, tk.END)
            text_widget.config(state=tk.DISABLED)

# Main
if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = PDFWatsonGUI(root)
        root.mainloop()
    except Exception as e:
        logging.critical(f"Application crashed: {e}")
        messagebox.showerror("Critical Error", f"Application crashed: {str(e)}\n\nSee log file for details.")
        traceback.print_exc()