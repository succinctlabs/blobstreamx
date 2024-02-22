#!/bin/bash

# Navigate to the contracts directory
cd contracts/

# Clean the Forge project
forge clean

# Bind libraries or dependencies
forge bind

# Navigate back to the parent directory
cd ..

# JSON file containing the ABI
ABI_JSON="contracts/out/BlobstreamX.sol/BlobstreamX.json"

# Use Python to extract the ABI field and save it
python3 -c "import json; f=open('$ABI_JSON'); data=json.load(f); print(json.dumps(data['abi']))" > abi/BlobstreamX.abi.json

# Ensure the abi directory exists
mkdir -p abi

