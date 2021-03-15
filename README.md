# RL-based SFC porototype

## Requirements

1. Ubuntu 20.04
2. Python 3.8 or higher
3. Network traffic data

## Installation

1. Clone the repository:
```bash
git clone https://github.com/mizolotu/izi
```
2. Create data directory:
```bash
cd izi
```
```bash
mkdir data
```
```bash
mkdir data/raw
```
3. Download network traffic PCAP data, e.g. from https://www.unb.ca/cic/datasets/ids-2018.html or any other source into ```data/raw``` directory, file path should look as follows:

data
  └── raw
      └── subdir (e.g. date)
             └── PCAP file

4. Install: 
  - libpcap-dev (apt), pcappy (pip), kaitaistruct (pip) 
  - numpy (pip), pandas (pip), sklearn (pip) 
  - tensorflow 2 (pip), tflite-runtime (pip)
  - libvirt (apt), vagrant (apt)
  - plotly (pip), orca (manual)
  - some other stuff

## Prepare ML classifiers

1. Split the PCAP data unto chunks: 
```bash
python3 split_data.py 
```

2. Create datasets:
```bash
python3 create_datasets.py
```
This may take some time, depending on the amount of the data and your computational power.

3. Train classifiers:
```bash
python3 train_classifiers.py -a <attack label> -s <sampling interval>
```
For correct attack labels, check parameter ```labels``` in file ```data/features/metainfo.json```. You should train at least one classifier for each attack label. Sampling interval is one of the following values: 1, 2, 4, 8 or 16. You can also change type of the model, its number of layers and number of neurons in each layer. You can implement more model types, e.g. anomaly detection models, models with attention and recurrent layers, etc.

4. When the classifiers are ready, run:  

```bash
python3 prepare_sources.py
```
This script will download SDN controller and convert tensorflow models into tflite format.

## Training RL agent

