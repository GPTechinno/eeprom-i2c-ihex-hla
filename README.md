# EEPROM I2C to iHex converter

## Features

* Construct an IntelHEX file accoring to i2c eeprom read and write
* Only 8-bits address EEPROM supported
* Print the iHex file in Terminal on trigger to specific data address (read or write), so choose wisely the last eeprom read/write address of your trace to have a final state of the memory printed.

## Example

![Example](https://raw.githubusercontent.com/GPTechinno/eeprom-i2c-ihex-hla/master/demo.png)