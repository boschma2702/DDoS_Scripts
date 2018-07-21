# Automatic DDoS Attack Rule Generation for SIDS applied to BRO

This repository contains all the code used for the research: Automatic DDoS Attack Rule Generation for
SIDS applied to BRO. This repository knows 5 python scripts, which are each elaborated in the sections below. Furthermore, also the JSON files used for this experiment are included in the folder json_files/. 
To actually run the scripts one needs to edit definitions.py, install various packages (see below) and need to download the pcap files from ddosdb.org. 


## attacker.py
This contains the code used to replay the attack. For this code to work, intended values must be filled in definitions.py. Also the package tcpreplay must be installed. This script needs to be run with sudo privileges. 

## generator.py
This contains the code that generates the signatures from the JSON files of DDoSDB. The JSON files used for the research can be found in the folder json_files/.

## ids.py
This contains the code that acts as the ids. For this code to work, intended values must be filled in definitions.py. Also Bro must be installed. This script needs to be run with sudo privileges. 

## definitions.py
This script contains all the variables that one needs to enter in order to let it work for their set-up. 

## send_to_attacker.py
The script is the one that sends a message towards the attacker and is executed by bro. 