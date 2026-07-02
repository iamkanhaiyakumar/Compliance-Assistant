import numpy as np
import faiss
from sentence_transformers import SentenceTransformer
import google.generativeai as genai
from openai import OpenAI

# ---------------------------------------------------------
# Local FAISS Indexing & Search
# ---------------------------------------------------------
class DocVectorStore:
    def __init__(self, text: str, chunk_size: int = 600, chunk_overlap: int = 100):
        self.model = SentenceTransformer("all-MiniLM-L6-v2")
        self.chunks = self._chunk_text(text, chunk_size, chunk_overlap)
        self.index = None
        
        if self.chunks:
            # Generate embeddings
            embeddings = self.model.encode(self.chunks, show_progress_bar=False)
            embeddings = np.array(embeddings).astype("float32")
            # Normalize for Cosine Similarity (IndexFlatIP + L2 normalization)
            faiss.normalize_L2(embeddings)
            self.dimension = embeddings.shape[1]
            self.index = faiss.IndexFlatIP(self.dimension)
            self.index.add(embeddings)

    def _chunk_text(self, text: str, size: int, overlap: int) -> list[str]:
        """Splits document text into overlapping chunks recursively."""
        words = text.split()
        if not words:
            return []
        chunks = []
        i = 0
        while i < len(words):
            chunk_words = words[i:i + size]
            chunks.append(" ".join(chunk_words))
            i += size - overlap
            if i >= len(words) - overlap:
                break
        return chunks

    def similarity_search(self, query: str, k: int = 4) -> list[tuple[str, float]]:
        """Returns top-k document chunks closest to the query based on Cosine Similarity."""
        if not self.index or not self.chunks:
            return []
            
        query_emb = self.model.encode([query], show_progress_bar=False)
        query_emb = np.array(query_emb).astype("float32")
        faiss.normalize_L2(query_emb)
        
        scores, indices = self.index.search(query_emb, k)
        
        results = []
        for score, idx in zip(scores[0], indices[0]):
            if idx != -1:
                results.append((self.chunks[idx], float(score)))
        return results

# ---------------------------------------------------------
# RAG Chat Q&A Execution
# ---------------------------------------------------------
def ask_compliance_copilot(
    query: str,
    vector_store: DocVectorStore,
    chat_history: list[dict],
    api_key: str,
    provider: str = "Gemini"
) -> str:
    """
    Formulates a RAG context query, retrieves relevant chunks from FAISS,
    and prompts the LLM to answer the user's questions securely.
    """
    if not api_key:
        return "Please configure your Gemini or OpenAI API Key in the sidebar to chat with the document."
        
    if not vector_store or not vector_store.chunks:
        return "No document text available. Please upload a file first."
        
    # Retrieve top 4 relevant chunks
    matches = vector_store.similarity_search(query, k=4)
    context_blocks = [chunk for chunk, score in matches if score > 0.15]
    
    if not context_blocks:
        context_str = "No specific sections of the document matched the semantic context of the query."
    else:
        context_str = "\n\n---\n\n".join(context_blocks)
        
    # Build chat history string
    history_str = ""
    for msg in chat_history[-6:]:  # include last 3 turns
        role_label = "User" if msg["role"] == "user" else "Assistant"
        history_str += f"{role_label}: {msg['content']}\n"
        
    prompt = f"""
    You are an expert AI Compliance Copilot. Your job is to answer questions about the uploaded document based ONLY on the retrieved document context below.
    If the context does not contain enough information to answer the question, state that the document does not specify this information.
    
    Document Context:
    ---
    {context_str}
    ---
    
    Conversational History:
    {history_str}
    
    User Query: {query}
    
    Guidelines:
    1. Base your answer strictly on the provided document context.
    2. Reference specific sections, numbers, or terms from the context.
    3. If there are compliance violations (GDPR, PCI DSS, DPDP) visible in the context, explain them clearly.
    4. Keep answers clear, structured, and professional.
    
    Assistant:
    """
    
    try:
        if provider == "Gemini":
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel("gemini-1.5-flash")
            response = model.generate_content(prompt)
            return response.text
        else:
            client = OpenAI(api_key=api_key)
            completion = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "You are a secure, context-abiding compliance consultant."},
                    {"role": "user", "content": prompt}
                ]
            )
            return completion.choices[0].message.content
    except Exception as e:
        return f"AI Copilot Error: Failed to generate response ({str(e)})."
