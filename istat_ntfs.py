# -*- coding: utf-8 -*-
"""
Created on Tue Apr  2 12:09:00 2019

@author: sferg
"""

import datetime
import struct

# Helpful dictionaries for the program
boot = {'bps': 0, 'spc': 0, 'bpc': 0, 'total sectors': 0, 'MFT start': 0, 'entry size': 0, 'index size': 0}
attr_types = {16: '$STANDARD_INFORMATION', 48: '$FILE_NAME', 128: '$DATA'}
std_info_flags = ['Read Only', 'Hidden', 'System', '', '', 'Archive', 'Device', '#Normal', 'Temporary', 'Sparse file', 'Reparse point', 'Compressed']

def parse_boot(data):
    boot['bps'] = as_le_unsigned(data[11:13])
    boot['spc'] = as_le_unsigned(data[13:14])
    boot['bpc'] = boot['spc'] * boot['bps']
    boot['total sectors'] = as_le_unsigned(data[40:48])
    boot['MFT start'] = as_le_unsigned(data[48:56]) * boot['bpc']
    
    entry_size = as_signed_le(data[64:65])
    if entry_size < 0:
        boot['entry size'] = 2 ** abs(entry_size)
    else:
        boot['entry size'] = entry_size * boot['bpc']
        
    index_size = as_signed_le(data[68:69])
    if index_size < 0:
        boot['index size'] = 2 ** abs(index_size)
    else:
        boot['index size'] = index_size * boot['bpc']
    return

def fixup(entry, fixup_arr):
    signature = as_le_unsigned(fixup_arr[0:2])
    fixup_arr = fixup_arr[2:]
    li_entry = bytearray(entry) # make the entry mutable

    for i in range(0, len(fixup_arr), 2):
        if as_le_unsigned(entry[(i//2 + 1)*boot['bps'] - 2:(i//2 + 1)*boot['bps']]) == signature:
            li_entry[(i//2 + 1)*boot['bps'] - 2:(i//2 + 1)*boot['bps']] = fixup_arr[i:i+2] # swap values if the signature matches the last two bytes
    return bytes(li_entry)

def parse_entry_header(entry, address):
    result = []
    
    result.append('MFT Entry Header Values:')
    result.append('Entry: ' + str(address) + '        Sequence: ' + str(as_le_unsigned(entry[16:18])))
    result.append('$LogFile Sequence Number: ' + str(as_le_unsigned(entry[8:16])))
    
    if as_le_unsigned(entry[22:24]) == 0x01:
        result.append('Allocated File')
    else:
        result.append('Directory')
        
    result.append('Links: ' + str(as_le_unsigned(entry[18:20])))    
    
    return result

def parse_attr_header(attr_header):
    result = {}
    
    result['type ID'] = as_le_unsigned(attr_header[0:4])
    result['length'] = as_le_unsigned(attr_header[4:8])
    result['flag'] = attr_header[8]
    if result['flag'] == 1:
        result['size'] = as_le_unsigned(attr_header[48:56])
        result['init size'] = as_le_unsigned(attr_header[56:64])
    result['name'] = bytes.decode(attr_header[as_le_unsigned(attr_header[10:12]):as_le_unsigned(attr_header[10:12]) + attr_header[9]])
    result['attribute ID'] = as_le_unsigned(attr_header[14:16])

    return result

def parse_standard_info(content):
    result = []
    
    flag_list = ''

    for i in range(len(std_info_flags)):
        if as_le_unsigned(content[32:36]) & 2**(i):
            flag_list += std_info_flags[i] # Concatenate flags
            
    result.append('Flags: ' + flag_list)
    
    if len(content) <= 48:
        result.append('Owner ID: 0') # avoid KeyError: 0 issue
    else:
        result.append('Owner ID: ' + str(as_le_unsigned(content[48:52])))
        
    result.append('Created:\t' + into_localtime_string(as_le_unsigned(content[0:8])))
    result.append('File Modified:\t' + into_localtime_string(as_le_unsigned(content[8:16])))
    result.append('MFT Modified:\t' + into_localtime_string(as_le_unsigned(content[16:24])))
    result.append('Accessed:\t' + into_localtime_string(as_le_unsigned(content[24:32])))
    
    result.append('')
    
    return result

def parse_file_name(content):
    result = []
    
    flag_list = ''
    for i in range(len(std_info_flags)):
        if as_le_unsigned(content[56:60]) & 2**(i):
            flag_list += std_info_flags[i] # Concatenate flags
    
    result.append('Flags: ' + flag_list)
    
    len_name = content[64]
    namespace = content[66:66 + 2*len_name] # adjust size for UTF-16 format
    name = bytes.decode(namespace, 'utf-16-le')
    
    result.append('Name: '+ name)
    result.append('Parent MFT Entry: ' + str(as_le_unsigned(content[0:4])) + ' \tSequence: ' + str(as_le_unsigned(content[6:8])))
    result.append('Allocated Size: ' + str(as_le_unsigned(content[40:48])) + '   \tActual Size: ' + str(as_le_unsigned(content[48:56])))
    result.append('Created:\t' + into_localtime_string(as_le_unsigned(content[8:16])))
    result.append('File Modified:\t' + into_localtime_string(as_le_unsigned(content[16:24])))
    result.append('MFT Modified:\t' + into_localtime_string(as_le_unsigned(content[24:32])))
    result.append('Accessed:\t' + into_localtime_string(as_le_unsigned(content[32:40])))
    
    result.append('')
    return result

def attr_list(attr, header):
    li = []
    li.append('Type: ' + attr_types[header['type ID']] + ' ({}-{})'.format(header['type ID'], header['attribute ID']))
    if header['name'] == '':
        li.append('Name: N/A')
    else:
        li.append('Name: ' + header['name'])
    if header['flag'] == 0:
        li.append('Resident')
        li.append('size: ' + str(as_le_unsigned(attr[16:20])))
    else:
        li.append('Non-Resident')
        li.append('size: ' + str(header['size']) + '  init_size: ' + str(header['init size']))
    
    return li

def cluster_run(data):
    run = []; row = []; split_run = []
    start_VCN = as_le_unsigned(data[16:24])
    prev_offset = start_VCN # first offset relative to start of FS
    run_list = data[as_le_unsigned(data[32:34]):] # isolate the run list

    next_run = 0
    
    while run_list[0] != 0:
        offset_bytes = run_list[0] >> 4 # num of offset bytes
        length_bytes = run_list[0] & 0b00001111 # num of length bytes
        
        offset = prev_offset + as_signed_le(run_list[length_bytes + 1:length_bytes + 1 + offset_bytes]) # starting cluster
        length = as_le_unsigned(run_list[1:length_bytes + 1]) # length of run
    
        for i in range(length): # append to one long list
            run.append(str(offset + i))
   
        next_run = offset_bytes + length_bytes # bytes offset to next run
        prev_offset = offset # store previous offset 
        run_list = run_list[next_run + 1:] # isolate next run
    
    for i in range(0, len(run), 8): # split into blocks of 8 for printing
        split_run.append(' '.join(run[i:i+8]))
        
    return split_run

def istat_ntfs(f, address, sector_size=512, offset=0):
    result = []
    data = f.read()
    data = data[offset * sector_size:] # isolate the offset on disk
    parse_boot(data) # establish key values
    
    mft = data[boot['MFT start']:] # isolate the MFT
    mft_entry = mft[address * boot['entry size']:(address * boot['entry size']) + boot['entry size']] # isolate the entry of interest
    
    fixup_offset = as_le_unsigned(mft_entry[4:6])
    fixup_size = 2 + (boot['entry size']//boot['bps']) * 2 # Swap fixup values if valid
    mft_entry = fixup(mft_entry, mft_entry[fixup_offset:fixup_offset + fixup_size]) 
    
    result.extend(parse_entry_header(mft_entry, address)) # HEADER
    result.append('')
    
    next_attr = as_le_unsigned(mft_entry[20:22]) # offset to first attribute
    attr = mft_entry[next_attr:] # isolate the first attribute
    header = parse_attr_header(attr) # get header values
    data_type = 16
    attr_header_list = []
    
    while data_type < 128:
        size = as_le_unsigned(attr[16:20])
        offset = as_le_unsigned(attr[20:22])
        content = attr[offset:offset + size] # isolate content area
        
        if data_type == 16 or data_type == 48: # only parse STD_INFO/FILE_NAME
            result.append(attr_types[header['type ID']] + ' Attribute Values:')
    
            attr_header_list.append('   '.join(attr_list(attr, header)))

            if header['type ID'] == 16:
                result.extend(parse_standard_info(content)) #RESIDENT, STD_INFO
            else:
                result.extend(parse_file_name(content)) # RESIDENT, FILE_NAME
        
        attr = attr[header['length']:] # isolate next attribute
        header = parse_attr_header(attr) # get next header values
        data_type = header['type ID'] # check for start of $DATA 
    
    attr_header_list.append('   '.join(attr_list(attr, header))) # add $DATA
    
    result.append('Attributes:')
    list(map(lambda x: result.append(x), attr_header_list))
    
    if header['flag'] == 1: # parse cluster run if $DATA is non-resident
        list(map(lambda x: result.append(x), cluster_run(attr)))

    return result

def as_le_unsigned(b):
    table = {1: 'B', 2: 'H', 4: 'L', 8: 'Q'}
    return struct.unpack('<' + table[len(b)], b)[0]

def as_signed_le(bs):
    if len(bs) <= 0 or len(bs) > 8:
        raise ValueError()

    signed_format = {1: 'b', 2: 'h', 4: 'l', 8: 'q'}

    fill = b'\xFF' if ((bs[-1] & 0x80) >> 7) == 1 else b'\x00'

    while len(bs) not in signed_format:
        bs = bs + fill

    return struct.unpack('<' + signed_format[len(bs)], bs)[0]

def into_localtime_string(windows_timestamp):
    """
    Convert a windows timestamp into istat-compatible output.

    Assumes your local host is in the EDT timezone.

    :param windows_timestamp: the struct.decoded 8-byte windows timestamp 
    :return: an istat-compatible string representation of this time in EDT
    """
    dt = datetime.datetime.fromtimestamp((windows_timestamp - 116444736000000000) / 10000000)
    hms = dt.strftime('%Y-%m-%d %H:%M:%S')
    fraction = windows_timestamp % 10000000
    return hms + '.' + str(fraction) + '00 (EDT)'


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Display details of a meta-data structure (i.e. inode).')
    parser.add_argument('-o', type=int, default=0, metavar='imgoffset',
                        help='The offset of the file system in the image (in sectors)')
    parser.add_argument('-b', type=int, default=512, metavar='dev_sector_size',
                        help='The size (in bytes) of the device sectors')
    parser.add_argument('image', help='Path to an NTFS raw (dd) image')
    parser.add_argument('address', type=int, help='Meta-data number to display stats on')
    args = parser.parse_args()
    with open(args.image, 'rb') as f:
        result = istat_ntfs(f, args.address, args.b, args.o)
        for line in result:
            print(line.strip())