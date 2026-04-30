# OpenMythos Local CPU Run

OpenMythos runs locally on CPU. CUDA is optional and only works on machines with an NVIDIA GPU and CUDA-enabled PyTorch.

## Install

```bash
cd ~/OpenMythos-0ai
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip wheel build
python -m pip install "setuptools<82"
python -m pip install -r requirements.txt
python -m pip install -e .
