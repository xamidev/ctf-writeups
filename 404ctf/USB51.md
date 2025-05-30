# USB51

Someone tried to exfiltrate data from our space agency, and we need to know what it was. To do this, we're given a USB packet capture in `pcapng` format. Opening it using Wireshark was my first reflex:

```
1	0.000000	host	2.3.2	USBMS	95	SCSI: Test Unit Ready LUN: 0x00
2	0.000037	2.3.2	host	USB	64	URB_BULK out
3	0.000054	host	2.3.1	USB	64	URB_BULK in
4	0.000150	2.3.1	host	USBMS	77	
5	1.173244	host	1.1.0	USBHUB	64	SET_FEATURE Request    [Port 3: PORT_SUSPEND]
```

As we can see, there is some communication going on between the host and a couple of USB devices. When ordering the packets by Length, we find something interesting:

```
43	3.364572	host	2.3.2	USB	48192	URB_BULK out
73	3.381362	host	2.3.2	USB	576	URB_BULK out
67	3.380135	host	2.3.2	USB	576	URB_BULK out
61	3.378983	host	2.3.2	USB	576	URB_BULK out
```

One packet is clearly standing out from the others; its size is 48192 bytes, whereas the others are usually 576 bytes or less. Let's investigate this one: we can copy its raw information as a hex stream:

```
255044462d312e370a25c3a4c3bcc3b6c39f0a322030206f626a0a3c3c2f4c656e6774682033203020522f46696c7465722f466c6174654465636f64653e3e0a73747265616d0a789c9d5a4d8fe3b811bdf7af30905b0e1ab2f80d180624cb0eb2c81e266920872087ddd9d960379b1964308b24ff3eaf8a12f561aa65ed34bac7966592557cf5
[redacted for simplicity]
```

This hex can then be transcribed to ASCII-printable characters with a tool like CyberChef:

```
@µC*ä.ÿÿS.....-.é©.h....§*	..ÿÿÿ.¼...¼..........................%PDF-1.7
%Ã¤Ã¼Ã¶Ã.
2 0 obj
<</Length 3 0 R/Filter/FlateDecode>>
[redacted for simplicity]
```

Looks like we found a PDF file! Let's look at the hex dump of a sample PDF to see how it's made on the inside:

```
00000000   25 50 44 46  2D 31 2E 37  0A 25 C3 A4  %PDF-1.7.%..
0000000C   C3 BC C3 B6  C3 9F 0A 32  20 30 20 6F  .......2 0 o
00000018   62 6A 0A 3C  3C 2F 4C 65  6E 67 74 68  bj.<</Length
00000024   20 33 20 30  20 52 2F 46  69 6C 74 65   3 0 R/Filte
00000030   72 2F 46 6C  61 74 65 44  65 63 6F 64  r/FlateDecod
0000003C   65 3E 3E 0A  73 74 72 65  61 6D 0A 78  e>>.stream.x
[redacted for simplicity]
00001D08   0A 3E 3E 0A  73 74 61 72  74 78 72 65  .>>.startxre
00001D14   66 0A 36 38  39 34 0A 25  25 45 4F 46  f.6894.%%EOF
00001D20   0A                                     .
```

We can see that a normal PDF file starts with `%PDF-1.7` and ends with `%%EOF`, followed by a newline character (in the dump, byte `0A`). We can now trim our hex dump to these borders, and then dump the whole hex into a fresh PDF, to examine it like a human would do:

```
$ xxd -r -p pdf_hex.txt > extracted.pdf
$ open extracted.pdf
```

When opening that PDF file, we see a report of the space agency, containing a binary piece of information, that we can convert to ASCII easily:

```
00110100 00110000 00110100 01000011 01010100 01000110 01111011 01010111
00110011 01011111 01100011 00110000 01001101 01000101 01011111 01001001
01001110 01011111 01110000 00110011 01100001 01000011 00110011 01111101
```

We have the flag! `404CTF{W3_c0ME_IN_p3aC3}`
