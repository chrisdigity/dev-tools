# Transaction Bot
This directory contains the TXBOT, a tool that allows you to take a typical address file of format:

WOTSADDR[2208]  
BALANCE[8]  
SECRET[32]

And dyamically send transactions to the network every n seconds, rotating through every known peer on the network.

## Recommended Usage
After succesful compilation, initalize and start the transaction bot with:
```
wget https://www.mochimap.net/startnodes.lst -O ./startnodes.lst
./txbot -cstartnodes.lst -p2095 -t1 -i<MCM_addr_filename> <transactionbot_queue_filename>
```
To continue a transaction bot, initalize and start the transaction bot with:
```
wget https://www.mochimap.net/startnodes.lst -O ./startnodes.lst
./txbot -cstartnodes.lst -p2095 -t1 <transactionbot_queue_filename>
```