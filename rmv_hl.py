import re
import os

def generate_output_path(filename, suffix='allrmved'):
    """ append a suffix to filename """
    if filename.endswith('.pdf'):
        name, ext = filename.rsplit('.', 1)
        return f'{name}_{suffix}.{ext}'
    else:
        return f'{filename}_{suffix}'

# def remove_hyperlinks(inp_file, format):
def remove_hyperlinks(inp_file):
    
    # if format == "File" or format == "file" :
    
    # FILE_PATH = "../Viruses_to_check/" + inp_file
    FILE_PATH = inp_file

    # if format == "Folder" or format == "folder":
    #     FILE_PATH = "../Viruses_to_check/Virus_changed1_Folder/" + inp_file
    # print(FILE_PATH)
    file = open(FILE_PATH, mode='rb')
    data = file.read()

    cleanr = re.compile(b'http+')
    text = re.sub(cleanr, b'acbd', data)

    inp_change = os.path.basename(FILE_PATH)
    output = generate_output_path(inp_change)
    
    nf = open(output, mode='wb')
    nf.write(text)
    nf.close()

    return output

    




