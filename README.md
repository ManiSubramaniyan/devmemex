Compile:
gcc devmemex.c -o devmemex

DevMemEx is derived from the Ubuntu DevMem2 sources and several new options have been added to the original version.

Usage: Devmemex <device/physical start address> <operation size/type> [ <write value>] / <Block size> /<block size> [<pattern> /<init string values>]
Operation size/types:
b    :    byte (u8) read/write    (devmem2)
h    :    half word (u16) read/write (devmem2)
w    :    word (u32) read/write (devmem2)
d    :    double word (u64) read/write (NEW)
s    :    show/display a block of device memory (NEW)
p    :    Write a fill pattern to a block of device memory (NEW)
i    :    Write a given sequence of (hex) words to a block of device memory (NEW)

In addition to the above:
n    :   N(o verify) is an attribute that can be added to any of the write operations (b/h/w/d/p/i)  (NEW)
        DevMem2 always reads first, writes and then reads back for a write operation. Adding this 'n' option
        avoids those verify reads and devmemex only writes without any reads when 'n' is specified.

Some examples:
1. devmemex 0xfebf2000 dn 0x55aaaa5512345678
   writes the 64 bit word (0x55aaaa5512345678) to the device memory 0xfebf2000 and does not verify; only writes
2. devmemex 0xfebf2800  s 0x180
   Displays 0x180 bytes of data starting at 0xfebf2800 similar to hex dump output (sequence of words, 4 words per line)
3. devmemex 0xfebf2000 p 0x10000 0xdeadbeef
   writes the pattern "deadbeef" repeatedly to device memory starting at 0xfebf2000 for a total length of 0x1000 bytes (4k)
4. devmemex 0xfebf2000 i 0x48  0x1111 0x2222 0x3333 0x4444 0x5555 0x6666 0x7777 0x8888 0x9999 0xaaaa 0xbbbb 0xcccc 0xdddd 0xeeee 0xffff
   initializes the device memory starting at 0xfebf2000 for a total length of 0x48 bytes the string of words given as args. If the input is less than 0x48 bytes, zeros are used for padding.
   If input is more than 0x48 bytes, it is truncated.

For the block operations (s,p,i), memcpy library function is used. The expectation is that the library memcpy is more efficient and can take care of newer CPU features such as movdir64b.

TODO/Known issues:
1. Parsing can be improved a bit. For e.g. the attribute 'n' (no verify) can only be given as the second letter. For e.g. 'dn' is valid but 'nd' is not valid.
2. Not written for performance at all; for e.g. for block operations device memory is only read/written to in multiples of 128B at a time.
3. Init input is only taken in as hex word values; for supporting other formats, have to change the code.
