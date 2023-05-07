# -*- coding: utf-8 -*-

# ref: https://github.com/QCloudHao/ncmdump

import binascii
import struct
import base64
import json
import os
from typing import Iterator

from Crypto.Cipher import AES

import eyed3
from eyed3.id3.frames import ImageFrame


def add_front_cover(mp3_file_path, image_data):
    try:
        audiofile = eyed3.load(mp3_file_path)
        audiofile.tag.images.set(ImageFrame.FRONT_COVER, image_data, "image/jpeg")
        audiofile.tag.save()
    except:  # noqa
        print(f"添加封面失败: {mp3_file_path}")


def dump(file_path, target_dir):
    os.makedirs(target_dir, exist_ok=True)

    # 十六进制转字符串
    # AES Key
    core_key = binascii.a2b_hex("687A4852416D736F356B496E62617857")
    meta_key = binascii.a2b_hex("2331346C6A6B5F215C5D2630553C2728")

    unpad = lambda s: s[0:-(s[-1] if type(s[-1]) == int else ord(s[-1]))]

    with open(file_path, "rb") as ncm_file:
        # get magic header
        header = ncm_file.read(8)
        # 字符串转十六进制
        assert binascii.b2a_hex(header) == b'4354454e4644414d'

        # read key length
        ncm_file.seek(2, 1)
        key_length = ncm_file.read(4)
        key_length = struct.unpack('<I', bytes(key_length))[0]

        # read key data
        key_data = ncm_file.read(key_length)
        key_data_array = bytearray(key_data)
        for i in range(0, len(key_data_array)):
            key_data_array[i] ^= 0x64
        key_data = bytes(key_data_array)

        # AES decode
        cryptor = AES.new(core_key, AES.MODE_ECB)
        key_data = unpad(cryptor.decrypt(key_data))[17:]
        key_length = len(key_data)
        key_data = bytearray(key_data)
        key_box = bytearray(range(256))
        last_byte = 0
        key_offset = 0
        for i in range(256):
            swap = key_box[i]
            c = (swap + last_byte + key_data[key_offset]) & 0xff
            key_offset += 1
            if key_offset >= key_length:
                key_offset = 0
            key_box[i] = key_box[c]
            key_box[c] = swap
            last_byte = c

        # handle meta
        meta_length = ncm_file.read(4)
        meta_length = struct.unpack('<I', bytes(meta_length))[0]

        meta_data = ncm_file.read(meta_length)
        meta_data_array = bytearray(meta_data)
        for i in range(0, len(meta_data_array)):
            meta_data_array[i] ^= 0x63
        meta_data = bytes(meta_data_array)
        meta_data = base64.b64decode(meta_data[22:])
        cryptor = AES.new(meta_key, AES.MODE_ECB)
        meta_data = unpad(cryptor.decrypt(meta_data)).decode('utf-8')[6:]
        meta_data = json.loads(meta_data)

        # crc
        check_crc32 = False
        if check_crc32:
            # TODO crc32 check
            pass
            # crc32 = ncm_file.read(4)
            # crc32 = struct.unpack('<I', bytes(crc32))[0]
        else:
            ncm_file.seek(4, 1)

        # read audio image data
        ncm_file.seek(5, 1)
        image_size = ncm_file.read(4)
        image_size = struct.unpack('<I', bytes(image_size))[0]
        image_data = ncm_file.read(image_size)

        file_name = ncm_file.name.split("/")[-1].split(".ncm")[0] + '.' + meta_data['format']
        target_file = os.path.join(target_dir, file_name)
        with open(target_file, 'wb') as mp3_file:
            while True:
                chunk = bytearray(ncm_file.read(0x8000))
                if not chunk:
                    break

                for i in range(1, len(chunk) + 1):
                    j = i & 0xff
                    chunk[i - 1] ^= key_box[(key_box[j] + key_box[(key_box[j] + j) & 0xff]) & 0xff]

                mp3_file.write(chunk)

        add_front_cover(target_file, image_data)
    return file_name


def list_all_ncm_file() -> Iterator[str]:
    # 获取当前文件夹下的 ncm 文件
    for file_name in os.listdir("./"):
        if os.path.isfile(f"./{file_name}") and file_name.endswith(".ncm"):
            yield file_name
            break


if __name__ == '__main__':
    all_ncm_files = list(list_all_ncm_file())
    total_count = len(all_ncm_files)
    for idx, file in enumerate(all_ncm_files, start=1):
        print(f"{idx}/{total_count} converting {file} ...")

        dump(f"./{file}", target_dir="./ncmTomp3")
