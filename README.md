# IoT Intrusion Detection System

This project is a Python-based Intrusion Detection System (IDS) for IoT network traffic. It trains a hybrid deep learning and machine learning model on the CICIoT2023 dataset, then uses a desktop packet-sniffing GUI to classify live traffic.

## Project Structure

```text
IDS/
+-- datacleaing.py
+-- requirements.txt
+-- scripts/
|   +-- hybrid_model.py
|   +-- train_hybrid.py
+-- Tool/
|   +-- async_predictor.py
|   +-- feature_extractor.py
|   +-- FlowManager.py
|   +-- ids_logger.py
|   +-- optimized_sniffer_gui.py
|   +-- packet_sniffer.py
|   +-- sniffer_gui.py
+-- screenshots/
    +-- accuracy.png
    +-- ss1.png
    +-- ss2.png
```

## Folders

- `scripts/` contains the training pipeline and hybrid IDS model implementation.
- `Tool/` contains the real-time packet sniffer GUI and prediction helpers.
- `screenshots/` contains project screenshots.
- `datasets/` is intentionally not included in Git because the CICIoT2023 dataset is large.
- `models/` is intentionally not included in Git because trained model files are generated binaries.

## Setup

Create and activate a Python environment:

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

On Windows, packet capture with Scapy usually requires Npcap and administrator privileges.

## Dataset

Download the CICIoT2023 dataset separately and place the CSV files here:

```text
datasets/CICIoT2023/
```

The training script expects the dataset path:

```text
../datasets/CICIoT2023/
```

relative to the `scripts/` folder.

## Train the Model

```powershell
cd scripts
python train_hybrid.py
```

The trained model is saved to:

```text
models/hybrid_dl_ml_model.pkl
```

This file is not committed to GitHub because it is large.

Download the trained model files from Google Drive:

```text
https://drive.google.com/drive/folders/1sodfWXD5BJtqnEUrER3l3cESC03zmEY4?usp=sharing
```

Place the required main model at:

```text
models/hybrid_dl_ml_model.pkl
```

Older or backup model files can stay separate unless you need them for testing.

## Run the IDS GUI

After training or downloading the model, make sure this file exists:

```text
models/hybrid_dl_ml_model.pkl
```

Then run:

```powershell
cd Tool
python optimized_sniffer_gui.py
```

For live packet capture, run the terminal as administrator.

## Notes

The repository tracks source code and documentation only. Large datasets, trained model binaries, virtual environments, logs, cache files, and packet captures are ignored by `.gitignore`.
