# Sensitive Data Detection & Compliance Assistant 🛡️

An AI-powered, enterprise-grade security and compliance auditor designed to scan documents (PDF, TXT, CSV), detect sensitive and confidential personal or business data (PII, credentials, corporate secrets), assess regulatory risks (GDPR, PCI DSS, DPDP), redact binary files, and provide an interactive AI compliance chat companion.

---

## 🚀 1. Setup Instructions

### Option A: Local Python Environment (Recommended for Development)

1. **Clone or Navigate to the Directory**:
   ```bash
   cd "d:/Sensitive Data Detection & Compliance Assistant"
   ```

2. **Create and Activate a Virtual Environment** (Optional but recommended):
   ```bash
   python -m venv venv
   # On Windows:
   .\venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Download the spaCy NLP Model**:
   ```bash
   python -m spacy download en_core_web_sm
   ```

5. **Install System Dependencies (Optional for OCR Support)**:
   - For image-based scanned PDF parsing, you need **Tesseract OCR** installed on your operating system.
   - [Download Tesseract for Windows](https://github.com/UB-Mannheim/tesseract/wiki) and add it to your system PATH.
   - If Tesseract is not installed, the app will run perfectly but disable scanned PDF scanning with a warning.

6. **Configure Environment Variables**:
   Open the generated [.env](file:///.env) file in the root folder and configure your keys. The app runs on **Groq** by default:
   ```env
   GROQ_API_KEY=your_free_groq_api_key
   ```

7. **Run the Streamlit Dashboard**:
   ```bash
   streamlit run app.py
   ```

---

### Option B: Docker Containerization (Production Ready)

Launch the entire stack (including models, configurations, and environment mappings) with a single command:

1. **Start the Container**:
   ```bash
   docker-compose up --build
   ```

2. **Access the Dashboard**:
   Open [http://localhost:8501](http://localhost:8501) in your browser.

---

## 🏛️ 2. Architecture Overview

The system uses a modular, layered python design:

```
[Uploaded Files] 
       ↓
[Document Parsers] ── (OCR fallback via PyMuPDF pixmaps & Tesseract)
       ↓
[Multi-Stage Scan Pipeline] 
  1. Regex Scanners (Aadhaar, PAN, CC, Email, Phone, IFSC)
  2. spaCy NER (Persons, Organizations, Locations)
  3. Entropy Engine (Passwords, API Keys, Credentials)
  4. LLM Verification (Staging Verification & Business secrets)
       ↓
[Compliance & Risk Assessor] ── (Logarithmic severity scoring & standard maps)
       ↓
[Redaction Engine] ── (HTML view overlays & PyMuPDF coordinate block redactions)
       ↓
[RAG QA Engine] ── (Sentence Transformers + FAISS similarity index)
       ↓
[Streamlit Interface] ── (Interactive charts, search, and download artifacts)
```

### Components:
- **`parsers.py`**: Extracts text from PDFs (using `pdfplumber`), CSVs (using `pandas`), and plain text. Implements PyMuPDF pixmap rendering to feed Tesseract for OCR if scanned pages are detected.
- **`detector.py`**: Executes regex and entropy scans. Employs a local **spaCy NER** model (`en_core_web_sm`) to flag Person Names, Organizations, and locations. Connects to OpenAI, Gemini, Groq, or Hugging Face for context verification and business strategic leaks.
- **`compliance.py`**: Formulates weighted risk scores, maps findings to GDPR, PCI DSS, DPDP, and ISO 27001, and issues priority remediation steps.
- **`redactor.py`**: Replaces sensitive data with tags in text files, and burns permanent black rectangular redactions on PDFs using PyMuPDF coordinate indexes.
- **`qa_engine.py`**: Splits document text into overlapping chunks, creates vectors using Sentence-Transformers, indexes them in a **FAISS** vector store, and triggers RAG chat.
- **`audit.py`**: Hashes uploaded files with SHA-256 to handle caching inside a SQLite database. Records session logs to a secure audit file.
- **`style.css`**: Contains premium glassmorphic layout definitions and CSS media queries for phone/minimization resizing.
- **`header_template.html`**: Premium gradient header layout.

---

## 🧠 3. AI/ML Approach Used

### Multi-Stage Scanner & Score Fusion
We combine fast deterministic engines (regex, Luhn checksums) with machine learning pipelines to optimize accuracy:
1. **Confidence Score Formulation**:
   $$Confidence = w_{pattern} \cdot S_{pattern} + w_{validation} \cdot S_{val} + w_{context} \cdot S_{ctx}$$
   - $S_{pattern}$ represents structural matching (Regex/Entropy).
   - $S_{val}$ represents checksum or LLM confirmation.
   - $S_{ctx}$ represents the semantic presence of keywords nearby.
2. **Logarithmic Weighted Risk Score**:
   To prevent score inflation from repetitive items, overall document risk is calculated logarithmically:
   $$Risk = \min\left(100, \sum_{k \in \text{Categories}} W_k \cdot \overline{C_k} \cdot \log_{2}(N_k + 1)\right)$$
   Where $W_k$ represents severity weights (Critical=25, High=15, Medium=5, Low=2), $\overline{C_k}$ is average confidence, and $N_k$ is frequency.

### RAG Document QA Copilot
- **Chunking**: Recursive splitting with a chunk size of 500 tokens and 50 tokens overlap.
- **Embeddings**: `all-MiniLM-L6-v2` via `sentence-transformers` for encoding.
- **Vector DB**: `FAISS` (IndexFlatIP with normalized vectors) for Cosine Similarity:
  $$\text{Similarity}(u, v) = \frac{u \cdot v}{\|u\| \|v\|}$$
- **Generation**: Chunks are retrieved and fed to Gemini 1.5 Flash (or GPT-4o-mini) to answer questions within compliance constraints.

---

## 🚧 4. Challenges Faced

1. **Scope and Namespace Collision (`UnboundLocalError`)**:
   During self-healing setup for spaCy downloads, importing `spacy.cli` inside local function blocks caused namespace collision with global imports. Resolved by importing `download` explicitly from `spacy.cli`.
2. **ReportLab Syntax Constraints**:
   Standard HTML line breaks (`<br>`) crashed ReportLab's paragraph parser. Resolved by rewriting them as self-closing `<br/>` tags to comply with report formatting engines.
3. **OCR Native Dependency Limitations**:
   Binary dependencies for poppler and pdf2image proved highly fragile on Windows environments. Resolved by leveraging PyMuPDF page pixmap rendering directly, removing extra binary requirements.
4. **Cloud Environment Permissions (spaCy OSError)**:
   Deploying to Streamlit Community Cloud threw an `OSError: Permission denied` when the runtime attempted to dynamically download and install the `en_core_web_sm` model wheel into the global virtualenv's `site-packages`. Resolved by specifying the wheel URL directly as a dependency in `requirements.txt` to trigger pre-build installation.
5. **Transformers Dependency Scans (`torchvision`)**:
   Streamlit's internal watcher scanned imported Hugging Face modules, causing a cascade of log warnings and `ModuleNotFoundError: No module named 'torchvision'`. Resolved by adding `torchvision` explicitly to `requirements.txt`.
6. **Responsive UI & Window Resizing**:
   Minimizing the browser screen squished the metric cards and caused tabs to wrap into multiple vertical lines. Resolved by separating styling into external `style.css` and `header_template.html` structures, implementing CSS media queries (`@media`), and forcing a horizontal, touch-scrollable flex layout on tabs.

---

## 🔮 5. Future Improvements

1. **Distributed Task Queue**:
   Use **Celery** backed by **Redis** to scale the scanning task worker pool, allowing background processing of thousands of documents concurrently.
2. **Fine-Tuned Local NER Models**:
   Deploy a custom-trained local **BERT-NER** model trained specifically on financial compliance documents to eliminate external API dependency.
3. **True Vector Redaction**:
   Develop a coordinate-mapping algorithm to automatically redact matching vector sections in CSV/Excel data sheets.

---

## 🌐 6. Working Prototype Deployment Link
- **Deployment URL**: [https://sensitive-data-detection-compliance-assistant.streamlit.app/](https://sensitive-data-detection-compliance-assistant.streamlit.app/)
- **Demo Video**: [Link to 3-Minute Demo Video](https://youtube.com/watch?v=demo-video-link) *(Walkthrough of dashboard, OCR scans, PDF highlights, and compliance exports)*
