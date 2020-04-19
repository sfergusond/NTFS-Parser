# NTFS-Parser
Python implementation of TSK's NTFS parser

# Usage

istat_ntfs.py |-h| |-o imgoffset| |-b sector_size| image address

-h: displays help output and exits

-o imgoffset: the offset of the beginning of the filesystem within the image (default = 0)

-b sector_size: the sector size of the filesystem (default = 512 bytes)

image: the name of the image to parse

address: the number of the inode to examine
