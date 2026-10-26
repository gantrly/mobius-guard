#!/bin/bash

# 1. Create the project directories
mkdir -p models/data
mkdir -p web

# 2. Setup Python environment for Stage 1 (Data Ops)
cd models
python -m venv .venv
source .venv/bin/activate

# Create requirements for the dataset generator
cat <<EOF > requirements.txt
datasets==2.18.0
huggingface_hub==0.22.2
pandas==2.2.1
tqdm==4.66.2
EOF

pip install -r requirements.txt
echo "Python ML environment ready."