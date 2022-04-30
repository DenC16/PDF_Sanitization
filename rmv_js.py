import os

def get_block_positions(data):
    """ isolate blocks starting with << and ending with >> """
    open_tag = b'<<'
    close_tag = b'>>'
    blocks = []

    def is_tag(data, i, tag):
        return data[i:i+2] == tag

    i = 0
    stack = []
    while i < len(data):
        is_open = is_tag(data, i, open_tag)
        is_close = is_tag(data, i, close_tag)
        assert False in (is_open, is_close), (
            f'can\'t be open and closed at the same time at {i}'
        )
        if is_open:
            stack.append(i)
            i += 1
        elif is_close:
            if len(stack) > 0:
                blocks.append((stack.pop(), i+2))
            i += 1
        i += 1
    #assert len(stack) == 0, f'unclosed block left'
    return blocks


def keep_leaves(blocks):

    for i, (start, end) in enumerate(blocks):
        _, prev_end = blocks[i-1]
        if i == 0 or start > prev_end:
            yield start, end


def filter_javascript(data, blocks):
    """ find javascript blocks """
    for start, end in keep_leaves(blocks):
        if b'/JavaScript' in data[start:end]:
            yield start, end


def patch_javascript(data, blocks):
    """ find javascript block and replace them with ';' characters"""
    result = bytearray(data)
    for start, end in filter_javascript(data, blocks):
        end_patch = None
        start_patch = None
        for i in range(start, end+1):
            if data[i:i+1] == b'(':
                start_patch = i+1
                break
        for i in range(end, start-1, -1):
            if data[i:i+1] == b')':
                end_patch = i
                break
        if None not in (start_patch, end_patch):
            result[start_patch:end_patch] = b';' * (end_patch - start_patch)
    return result


def check_result(data, result, blocks):
    """ display original and patched lines together for comparison """
    for start, end in filter_javascript(data, blocks):
        print()
        print(data[start:end].decode('utf-8'))
        print(result[start:end].decode('utf-8'))


def check_is_pdf(path, data):
    """ exit if file doesn't start with PDF magic number """
    if not data.startswith(b'%PDF'):
        print(f'{os.path.realpath(path)} isn\'t a pdf')
        exit(2)


def generate_output_path(filename, suffix='ch'):
    """ append a suffix to filename """
    if filename.endswith('.pdf'):
        name, ext = filename.rsplit('.', 1)
        return f'{name}_{suffix}.{ext}'
    else:
        return f'{filename}_{suffix}'


# def remove_javascript(file, format):
def remove_javascript(file):

    # if format == "File" or format == "file":
    # FILE_PATH = "../Viruses_to_check/" + file
    FILE_PATH = file

    # if format == "Folder" or format == "folder":
    #     FILE_PATH = "../Viruses_to_check/Virus_Folder/" + file
        
    f = open(FILE_PATH, 'rb')
    data = f.read()

    #check_is_pdf(pdf, data)

    blocks = get_block_positions(data)
    result = patch_javascript(data, blocks)

    #check_result(data, result, blocks)
    output = generate_output_path(FILE_PATH)
    nf = open(output, 'wb')
    nf.write(result)
    
    return output
