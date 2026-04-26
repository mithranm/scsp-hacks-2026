# SCSP Hacks 2026 - Team Cortex

## Project Structure

```
genai-fingerprinting/   GenAI traffic fingerprinting (models, data, results)
src/                    Data collection and analysis
frontend/               Frontend application
data_collection/        Data collection scripts
data/                   Geographic and shared data
```

## Dependencies

Install [pybgpstream](https://github.com/CAIDA/pybgpstream) from source.

Install PyTorch with CUDA (check your version with `nvidia-smi`):
```bash
pip install torch --index-url https://download.pytorch.org/whl/cu124
```

Then install the rest:
```bash
pip install -r requirements.txt
```

## Data

Geographic data is taken from MaxMind, needs to be placed in the data folder:

```
data/
├── GeoLite2-ASN/
│   ├── GeoLite2-ASN.mmdb
│   ├── COPYRIGHT.txt
│   └── LICENSE.txt
└── GeoLite2-City/
    ├── GeoLite2-City.mmdb
    ├── COPYRIGHT.txt
    ├── LICENSE.txt
    └── README.txt
```

## GenAI Fingerprinting

Network traffic classification to distinguish GenAI traffic (ChatGPT, Gemini, Grok, Perplexity) from regular traffic using deep learning on raw packet sequences.

Feature extraction must run first:
```bash
cd genai-fingerprinting
python preprocessing/feature_extraction.py
```

Then run any model:
```bash
python models/baseline/training.py      # RF + Gradient Boosting
python models/transformer/training.py   # Transformer
python models/bilstm/training.py        # BiLSTM
python models/cnn_lstm/training.py      # CNN-LSTM
python models/ensemble/training.py      # Ensemble
```
