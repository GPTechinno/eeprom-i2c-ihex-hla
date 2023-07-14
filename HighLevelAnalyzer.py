# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, NumberSetting
import struct

# inspired from fasthex
IHEX_SC = ":"#0x3A #collon ":" is start code for all valid lines
#the record type that represents
IHEX_RECT_DT    = 0x0 #data 
IHEX_RECT_EOF   = 0x1 #End of File
IHEX_RECT_OADDR = 0x4 #offset address, e.g. the first part of a 32bit address

def calc_chksum(data):
    """
    calculates the checksum for data
    @param data: data
    @return: the checksum
    """
    return (0x100 - sum(data)) & 0xFF

def concat_hex_line(laddr,rec_t,data=b""):
    """
    concatenates a line of a hex file
    @param laddr: the line address where this data starts
    @param rec_t: the record type of this line
    @param data: the data of this line
    @return: a line of a hex file
    """
    L = bytearray()
    L.append(len(data))
    L.extend(struct.pack(">H",laddr))
    L.append(rec_t)
    L.extend(data)
    L.append(calc_chksum(L))
    return ":"+L.hex().upper()

def generate_hex_lines(addr,data,linewidth=0x20):
    """
    generates lines for a hex file
    @param addr: the address where data starts
    @param data: the data
    @param linewidth: the byte count how many bytes should be written in a single line
    @return: a list of lines
    """
    #Todo: this could be easily changed to a generator
    lines = []
    lhaddr = -1
    for idx,caddr in enumerate(range(addr,len(data)+addr,linewidth)):
        laddr = caddr & 0xFFFF #lower 16bit
        if caddr & 0xFFFF0000 != lhaddr:
            lhaddr = caddr & 0xFFFF0000 #upper 16 bit
            #write a 04 line
            lines.append(concat_hex_line(laddr=0,rec_t=IHEX_RECT_OADDR,data=struct.pack(">H",lhaddr >> 16)))
        lines.append(concat_hex_line(laddr=laddr,rec_t=IHEX_RECT_DT,data=data[idx*linewidth:(idx+1)*linewidth]))
    return lines

class intelhex():

    def __init__(self):
        """
        intelhex class constructor
        """
        self.contents = []#contents will be a list of (addr,bytearray)-tupples

    def to_str(self):
        """
        concats the object contents to be written to a hex file
        @return: a multi line string
        """
        lines = []
        for addr,data in self.contents:
            lines.extend([line for line in generate_hex_lines(addr,data)])
        lines.append(concat_hex_line(laddr=0,rec_t=IHEX_RECT_EOF))
        return "\n".join(lines)
    
    def putz(self,baddr,data):
        """
        puts a byte string at a given address
        @param baddr: the byte address where to put data
        @param data: the data to be put
        """
        blen = len(data)
        # print(baddr,blen,data,self.contents)
        added = False
        for addr,_data_ in self.contents:
            if (addr < baddr) and ((addr+len(_data_)) > (baddr+blen)):
                offset = baddr-addr
                _data_[offset:offset+blen] = data
                added = True
                break
            if (addr < baddr) and ((addr+len(_data_)) == baddr):
                _data_ += data
                added = True
                break
        if not added:
            self.contents.append((baddr,bytearray(data)))
        # print(self.contents)
        return


# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    """EEPROM I2C to iHex converter High Level Analyzer."""

    eep_i2c_addr = NumberSetting(label='EEPROM I2C Address (7-bits)', min_value=0x50, max_value=0x7f)
    last_address = NumberSetting(label='Address to trigger iHex printing in Terminal', min_value=0x00, max_value=0xff)

    def __init__(self):
        self._for_us: bool = False
        self._read: bool = False
        self._address: int = 0
        self._byte_pos: int = 0
        self._eep_data = intelhex()

    def decode(self, frame: AnalyzerFrame):
        if 'error' in frame.data:
            return
        if frame.type == 'start':
            self._byte_pos = 0
        elif frame.type == 'address':
            if frame.data['address'][0] == self.eep_i2c_addr:
                self._for_us = True
            else:
                self._for_us = False
                return
            self._read = frame.data['read']
        elif frame.type == 'data':
            if not self._for_us:
                return
            raw = frame.data['data'][0]
            if self._read:
                self._eep_data.putz(self._address+self._byte_pos, frame.data['data'])
            else:
                if self._byte_pos == 0:
                    self._address = raw
                else:
                    self._eep_data.putz(self._address+self._byte_pos-1, frame.data['data'])
            self._byte_pos += 1
        elif frame.type == 'stop':
            if not self._for_us:
                return
            if self._address == self.last_address and self._read:
                print()
                print(f"---------- EEPROM @0x{int(self.eep_i2c_addr):02X} iHex ----------")
                print(self._eep_data.to_str())
                print("---------------------------------------")
