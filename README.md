# smart-meter-server
esp32 driven energy logging and serving for laser cost management

## Setup
esp32-laser.ino:23/25 - set values for the authorization of data on the SD-Card
esp32-laser.ino:47 - Set password for accessing saved usage times
esp32-laser.ino:270 - Set username & password for the smart socket to access wifi (if no authorization is activated for the smart socket, simply remove the whole line...)