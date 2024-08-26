import re
import argparse
import os
import time

def print_banner():
    banner = r"""
 _______________
< ROKRAT - North Korean Decryption >
File Found: 230130.bat
Decrypt by: Divzin
SHA1: fe6722b92f25b0605b0281327c0470bfd03f1398

 ---------------
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||                                                                                     
     """
    print(banner)

def read_file(file_path):
    try:
        with open(file_path, 'r', encoding='latin1') as file:
            content = file.read()
        return content
    except Exception as e:
        print(f"Erro ao ler o arquivo: {e}")
        return None

def extract_hex_string(content):
    match = re.search(r'\$eric5="""(.*?)""";', content)
    if match:
        return match.group(1)
    else:
        print("Nenhuma string hexadecimal encontrada no arquivo .bat")
        return None

def extract_ppams_string(content):
    match = re.search(r'\$ppams\s*=\s*"\$eric5=""".*?""";(.*?);\s*Invoke-Command -ScriptBlock', content, re.DOTALL)
    if match:
        return match.group(1).strip()
    else:
        print("Nenhuma string $ppams encontrada no arquivo .bat")
        return None

def decrypt_hex_string(hex_string):
    decrypted_string = ""
    for i in range(0, len(hex_string), 2):
        hex_pair = hex_string[i:i+2]
        decrypted_string += chr(int(hex_pair, 16))
    return decrypted_string

def extract_links(decrypted_string):
    links = re.findall(r'(https?://[^\s]+)', decrypted_string)
    return links

def extract_file_paths(content):
    paths = re.findall(r'[A-Za-z]:\\[^\s]+', content)
    return paths

def extract_important_strings(content):
    links = extract_links(content)
    paths = extract_file_paths(content)
    return links, paths

def process_lnk_files(directory):
    lnk_files = [f for f in os.listdir(directory) if f.endswith('.lnk')]
    all_links = []
    all_paths = []
    for lnk_file in lnk_files:
        lnk_path = os.path.join(directory, lnk_file)
        content = read_file(lnk_path)
        if content:
            links, paths = extract_important_strings(content)
            all_links.extend(links)
            all_paths.extend(paths)
    return all_links, all_paths

def main():
    parser = argparse.ArgumentParser(description="Decrypt hex string from a .bat file and extract important strings.")
    parser.add_argument("-f", "--file", type=str, required=True, help="Path to the .bat file")
    args = parser.parse_args()

    print_banner()

    content = read_file(args.file)
    if content:
        print("\nDecrypt em andamento...")
        time.sleep(6)
        
        hex_string = extract_hex_string(content)
        ppams_string = extract_ppams_string(content)
        if hex_string:
            decrypted_string = decrypt_hex_string(hex_string)
            links, paths = extract_important_strings(decrypted_string)
            bat_links, bat_paths = extract_important_strings(content)
            
            print("HEXADECIMAL DECRYPT:")
            print(decrypted_string)
            print("\nLINKS FOUND:")
            for link in links:
                print(link)
            print("\nPATHS FOUND:")
            for path in paths:
                print(path)
            print("\nString $ppams:")
            print(ppams_string)
            print("\nIMPORTANT STRINGS FROM .bat FILE:")
            for link in bat_links:
                print(f"Link: {link}")
            for path in bat_paths:
                print(f"Path: {path}")

            directory = os.path.dirname(args.file)
            lnk_links, lnk_paths = process_lnk_files(directory)
            if lnk_links or lnk_paths:
                print("\nIMPORTANT STRINGS FROM .lnk FILES:")
                for link in lnk_links:
                    print(f"Link: {link}")
                for path in lnk_paths:
                    print(f"Path: {path}")

            print("\nDECRYPT FOUND:")
            decrypt_code = r""";$bulst="""""";for($i=0;$i -le $eric5.Length-2;$i=$i+2){$NTMO=$eric5[$i]+$eric5[$i+1];$bulst= $bulst+[char]([convert]::toint16($NTMO,16));};Invoke-Command -ScriptBlock ([Scriptblock]::Create($bulst));";Invoke-Command -ScriptBlock ([Scriptblock]::Create($ppams));"""
            print(decrypt_code)

if __name__ == "__main__":
    main()
