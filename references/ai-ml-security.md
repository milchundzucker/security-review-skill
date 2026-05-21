# AI/ML-Sicherheit (jenseits LLM)

**Wird geladen, wenn** ML-Pipelines erkannt werden: `torch`, `tensorflow`, `keras`, `sklearn`, `xgboost`, `onnx`, `mlflow`, `kubeflow`, `sagemaker`, `vertexai`, `dvc`, `wandb`, `huggingface_hub`, `transformers`, `diffusers`, `joblib.load`, `pickle.load`, `torch.load`, `*.pkl`, `*.h5`, `*.onnx`, `*.safetensors`, `*.gguf`.

Ergänzt `owasp-llm-top10.md` um Angriffsklassen im klassischen ML-Stack und der MLOps-Pipeline.

## 1. Pickle / Joblib / torch.load — Arbitrary Code Execution

**CWE-502** — Critical. Pickle und alle Pickle-Wrapper sind Deserialization-RCE-Vektoren. Modelle aus dem Internet laden = Code-Ausführung.

**Detection:**
```bash
rg -n "pickle\\.load|joblib\\.load|torch\\.load|cloudpickle\\.load|dill\\.load" --type=py
rg -n "from_pretrained|hub\\.load|hf_hub_download" --type=py
rg -n "ModelLoader|load_model.*pkl|load_model.*pt" --type=py
```

**Unsafe:**
```python
import joblib
model = joblib.load(request.files['model'].stream)  # ⚠️ RCE
import torch
model = torch.load('user_uploaded.pt')  # ⚠️ RCE
```

**Safe — sichere Formate:**
```python
# safetensors (HuggingFace) — kein Code möglich
from safetensors.torch import load_file
state_dict = load_file('model.safetensors')

# ONNX — Computational Graph, kein Python-Code
import onnxruntime as ort
sess = ort.InferenceSession('model.onnx')

# Wenn pickle unvermeidbar: weights_only=True (PyTorch ≥ 2.6 default)
model = torch.load('model.pt', weights_only=True)

# Letzte Resorte: Hash-Allowlist + Signature-Verification
import hashlib
expected = '5f4dcc3b5aa765d61d8327deb882cf99'
with open('model.pt', 'rb') as f:
    data = f.read()
assert hashlib.sha256(data).hexdigest() == expected
```

## 2. Model Provenance / Supply Chain

**CWE-345 / OWASP A08** — Modell aus HuggingFace Hub geladen, ohne Verifikation.

**Unsafe:**
```python
from transformers import AutoModel
model = AutoModel.from_pretrained('unknown-user/cool-model')
# ⚠️ Lädt arbiträre Files, ggf. mit pickle
```

**Safe:**
```python
model = AutoModel.from_pretrained(
    'org/model',
    revision='abc123...',           # Commit-Hash, kein Tag/Branch (mutable)
    use_safetensors=True,           # nur safetensors
    trust_remote_code=False,        # niemals True bei untrusted
)
```

**`trust_remote_code=True` ist Critical** — lässt arbiträren Python-Code aus dem Repo ausführen.

**Detection:**
```bash
rg -n "trust_remote_code\\s*=\\s*True|trust_remote_code=True" --type=py
rg -n "from_pretrained\\(['\"]" -A 3 --type=py | rg -v "revision="
```

## 3. Training Data Poisoning

**CWE-1426 / OWASP ML02** — Angreifer kann Training-Daten kontaminieren.

**Risikofaktoren:**
- Daten aus User-Submissions ohne Moderation
- Crawled Web-Daten ohne Allowlist
- Externe Labeling-Services
- Re-Training mit Live-Traffic (Feedback Loop / Online Learning)

**Mitigationen — im Code zu prüfen:**
- Provenance-Tracking (DVC, MLflow Tracking)
- Anomaly-Detection vor Training (Distribution Shift Check)
- Sample-Signing für kuratierte Sets
- Differential Privacy beim Training (DP-SGD)
- Robust-Training-Verfahren (Trimmed Mean Aggregation bei Federated Learning)

**Detection:**
```bash
rg -n "online_learning|partial_fit|incremental_fit" --type=py
rg -n "user_feedback|implicit_label" --type=py
```

## 4. Adversarial Inputs / Evasion

**CWE-1039 / OWASP ML01** — Eingabe leicht verändert → Modell klassifiziert falsch.

**Mitigationen:**
- Input-Preprocessing (JPEG-Recompression bei Bildern bricht viele Adversarial Patterns)
- Confidence-Threshold + Human-in-the-Loop
- Adversarial Training während Training
- Defensive Distillation
- Ensemble-Decision

**Im Code-Review prüfen:**
- Werden Modell-Outputs in sicherheitskritischen Entscheidungen verwendet (Auth, Fraud, Content-Moderation)?
- Gibt es Fallback-Pfade?
- Werden Confidence Scores ausgewertet (nicht nur argmax)?

## 5. Model Inversion / Extraction

**CWE-200 / OWASP ML03 / ML05** — Angreifer rekonstruiert Trainingsdaten oder klont das Modell.

**Risikofaktoren:**
- Modell gibt rohe Logits/Probabilities zurück (statt nur Klassen)
- Keine Rate-Limits auf Inference-Endpoint
- Keine Detection auf Pattern-Probing

**Mitigationen:**
- Nur Top-K-Klassen + gerundete Confidence zurückgeben
- Rate-Limit pro Account/IP
- Watermarking
- DP-SGD beim Training (verhindert Membership-Inference)

```python
# Unsafe
@app.post('/predict')
def predict(x):
    return {'logits': model(x).tolist()}  # leakt zu viel

# Safer
@app.post('/predict')
@rate_limit('100/hour')
def predict(x):
    p = softmax(model(x))
    top = torch.topk(p, k=3)
    return {'top3': [{'class': cls, 'confidence': round(c.item(), 2)}
                     for cls, c in zip(top.indices, top.values)]}
```

## 6. Membership Inference

**OWASP ML07** — "War Datensatz X im Training?" → DSGVO-Verstoß, IP-Leak.

**Detection im Code:**
- Wird das Modell auf PII trainiert?
- Werden Output-Distributions ohne Glättung exposed?
- Gibt es Confidence-Scores im Response?

**Mitigation:** DP-SGD oder PATE.

## 7. Prompt Injection in Multimodalen Modellen

Bei Vision-Language-Modellen (LLaVA, GPT-4V): Bilder können Prompt-Injection enthalten.

→ siehe `owasp-llm-top10.md` für Text-Prompt-Injection.

**Spezifisch multimodal:**
```bash
rg -n "image_url|image_base64|vision_model" --type=py --type=ts
```

Bilder vor Verarbeitung normalisieren (Re-encoding), QR-Code-Detection, Pixel-OCR-Filter falls relevant.

## 8. MLflow / Kubeflow / Sagemaker Pipeline-Security

**CWE-732 / CWE-552** — ML-Tracking-Server speichert oft Modelle in offenen S3-Buckets, Artefakte enthalten Secrets.

**Detection:**
```bash
rg -n "mlflow\\.set_tracking_uri|mlflow\\.log_artifact" --type=py
rg -n "MLFLOW_TRACKING_URI|MLFLOW_S3_ENDPOINT" --type=yaml --type=py
rg -n "sagemaker\\.create_model|sagemaker\\.deploy" --type=py
```

**Prüfen:**
- Ist der MLflow-Server authentifiziert? (Default = offen!)
- S3-Bucket mit Modellen public?
- Werden Secrets als Artefakte geloggt (Config-Files, .env)?
- Wer kann Modelle ins Registry pushen?

## 9. Notebook-Security (Jupyter / Colab)

**CWE-94 / CWE-78** — Notebooks im Repo enthalten oft:
- Hardcoded Credentials (`!aws s3 cp`, `!gcloud auth`)
- Public-Outputs mit PII
- Schädliche Magic-Commands

**Detection:**
```bash
rg -n "^!|^%(sh|bash|env)|os\\.system|subprocess" -g "*.ipynb"
rg -n "AKIA|sk-[A-Za-z0-9]{20}|password\\s*=" -g "*.ipynb"
```

## 10. Vector Database / RAG-Pipeline-Security

**CWE-1039 + Embedding-spezifisch** — Vektoren-DBs (Pinecone, Weaviate, pgvector, Chroma, Milvus) haben eigene Risiken.

**Spezifika:**
- **Embedding Inversion**: Embeddings können (teilweise) zurück in Text rekonstruiert werden → keine PII direkt embedden ohne Sanitization.
- **Namespace-Crossover**: Multi-Tenant ohne Namespace/Filter → Cross-Tenant-Retrieval.
- **Injection via Source-Documents**: indirekte Prompt-Injection (siehe `owasp-llm-top10.md`).
- **Authorization**: Filter-Bypass durch `metadata`-Manipulation:

```python
# Unsafe
results = index.query(vector=q, filter={'tenant_id': request.json['tenant_id']})
# ⚠️ Angreifer setzt tenant_id

# Safe
results = index.query(vector=q, filter={'tenant_id': current_user.tenant_id})
```

## 11. Feature-Store / Online-Inference-Cache

**CWE-639** — Features pro User gecached, falscher Cache-Key → Cross-User-Datenleck.

**Pattern:**
```python
@cache(key=lambda u: f'features:{u.id}')
def get_features(user):
    return feature_store.get(user.id)
# Wenn Cache key kollidiert (z.B. Hash-Truncation, Multi-Tenant) → Leak
```

## 12. ONNX / TFLite — Custom Operators / Plugins

**CWE-829** — ONNX Custom Ops und TFLite Custom Delegates laden Native Code.

**Detection:**
```bash
rg -n "register_custom_op|register_kernel|CustomDelegate" --type=cpp --type=py
rg -n "ort\\.set_default_logger_severity|providers=\\['CUDAExecutionProvider'" --type=py
```

**Risiko:** Modell-File referenziert Custom-Op-Library → wird beim Load nachgeladen → RCE.

## 13. Federated Learning — Byzantine Workers

**CWE-345** — Bei Federated Learning kann ein bösartiger Client schädliche Gradients senden.

**Mitigationen im Code:**
- Robust Aggregation (Krum, Trimmed Mean, Median)
- Sample-Size-Validation
- Client-Authentifizierung mit Hardware Attestation
- Server-Side Anomaly Detection auf Gradient-Norms

## 14. Model Card / Datasheet als Sicherheitskontrolle

Compliance- und Audit-Anforderung (EU AI Act, NIST AI RMF):
- Welche Daten? Welche Bias-Tests? Welche Threats analysiert?
- Im Code-Review: existiert `MODEL_CARD.md` / `DATASHEET.md`?

## 15. AI-Act Risikoklassen-Awareness

**EU AI Act** — Hochrisiko-Systeme (Biometrie, Recruiting, Credit-Scoring, Strafverfolgung, kritische Infrastruktur) haben Pflicht zu:
- Logging der Inferences
- Human Oversight
- Robustheit-Tests
- Bias-Assessment

→ Im Code prüfen: Logging vorhanden? Override-Mechanismus? Test-Suite mit demografischen Slices?

→ siehe auch `privacy-compliance.md` für DSGVO Art. 22 (automatisierte Einzelentscheidung).

## 16. GPU-Shared-Tenancy

**CWE-200** — On-Premise oder Cloud-GPUs werden geteilt. CUDA-Side-Channels (Rowhammer-GPU, MIG-Leaks) → Modell-Weights-Leak möglich.

**Mitigation:**
- Dedicated GPU-Instanzen für sensitive Workloads
- Memory-Clearing vor Job-End
- MIG/MPS-Isolation prüfen

## 17. Notebook-as-Service-Risiken

Kaggle / Colab / SageMaker Studio:
- Token mit `repo:write`-Scope in `~/.netrc`
- Cloud-Credentials in `~/.aws/credentials`
- Secrets in Notebook-Outputs gespeichert → committed → leak

## 18. Inference-Endpoint Authentication

**OWASP API1+API2** — ML-Endpoints werden oft "schnell deployed" ohne Auth.

**Detection:**
```bash
rg -n "@app\\.(post|get)\\(['\"]/(predict|infer|score)" --type=py
rg -n "torchserve|triton-inference-server|kfserving|seldon" 
```

**Prüfen:** API-Key, OAuth, Rate-Limit, Audit-Log.

## 19. Model-Output → Sink ohne Encoding

Wenn Modell-Output direkt in HTML, SQL, OS-Cmd, JS landet:
- LLM/Generator gibt XSS-Payload zurück → wird gerendert
- Klassifikator gibt String zurück → in SQL-Query interpoliert (Möglichkeit!)

→ Behandle Modell-Output als untrusted user input. Siehe `owasp-llm-top10.md` "Insecure Output Handling".

## 20. Bias / Fairness — Audit-Relevanz

Nicht klassische "Sicherheit", aber Compliance-Risiko:
- Fairness-Metriken pro demografische Slice
- Disparate-Impact-Test (4/5-Regel)
- Counterfactual Fairness

Im Code: Existieren Fairness-Tests in der CI?

## Severity-Heuristik

| Befund | Default-Severity | Eskalation |
|--------|------------------|------------|
| pickle.load auf User-Input | Critical | bestätigte RCE-Quelle |
| torch.load ohne weights_only | High | öffentlicher Endpoint → Critical |
| trust_remote_code=True | Critical | aus Internet → Critical |
| Modell ohne Pinning (Hash/Revision) | High | Supply-Chain-Risk |
| MLflow ohne Auth | High | exponiert ins Internet → Critical |
| Notebook mit Secrets im Repo | High | git history → Critical |
| Multi-Tenant ohne Namespace-Filter | High | PII → Critical |
| ONNX Custom Op aus Untrusted | High | RCE → Critical |
| Endpoint ohne Auth | High | sensitive Modelle → Critical |
| Model-Output → unencoded Sink | High | XSS/SQLi-Chain → Critical |
| Online-Learning ohne Validation | Medium | Public-Input → High |
| Model-Inversion-Risk (rohe Logits) | Medium | PII-Modell → High |
| AI-Act-Hochrisiko ohne Logging | High | Compliance-Pflicht |

## Referenzen

- OWASP ML Top 10 (2023)
- OWASP LLM Top 10 (für überlappende Themen)
- NIST AI Risk Management Framework (AI RMF 1.0)
- EU AI Act (Verordnung 2024/1689)
- MITRE ATLAS (Adversarial Threat Landscape for AI Systems)
- "Pickle is wat de pot schaft" — PyTorch Security Best Practices
- HuggingFace Security Best Practices
- CWE-502, CWE-829, CWE-1039, CWE-1426
