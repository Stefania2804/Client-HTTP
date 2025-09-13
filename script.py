import re

RE_EXTRACT_LIST_ITEM = r"^\s*(?:movie\s*)?#([0-9]+)(?:\s*:)?\s*(.+)\s*"

output_din_client = """  ID: 14271
  Title: Top IMDB
  Owner: test_1747393106_dtiCe9
  Movies:
    #32556 The Dark Knight
    #32566 The Lord of the Rings 1-3""" # Asigură-te că newlines sunt corecte aici

matches = re.findall(RE_EXTRACT_LIST_ITEM, output_din_client, re.IGNORECASE | re.MULTILINE)
print(matches) 
# Ar trebui să printeze: [('32556', 'The Dark Knight'), ('32566', 'The Lord of the Rings 1-3')]