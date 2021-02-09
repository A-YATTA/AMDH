import os


def check_header(header):
    if header == "504b0304":
        return "JAR"

    if header == "7f454c46":
        return "ELF"

    return "UNKNOWN"


def write_file_to_dir(output_dir, filename, content):
    if not os.path.isdir(output_dir):
        os.makedirs(output_dir)
    if not output_dir[:-1] == '/':
        output_dir += "/"

    f = open(output_dir + filename, 'wb')
    f.write(content)
    f.close()
