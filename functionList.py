import os

def get_file_type(filepath):
    # if it's path/to/file.txt
    # returns .txt
    basename = os.path.basename(filepath)
    _, extension = os.path.splitext(basename)

    return extension

def get_base_file_name(filepath):
    # if it's path/to/file.txt
    # returns file.txt
    basename = os.path.basename(filepath)
    basename_without_extension = os.path.splitext(filepath)[0]
    return basename_without_extension