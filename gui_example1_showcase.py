#!python
# dummy script
'''
usage: $0 input_csv*csv variable_csv:input_csv some_trully_realy_long_label logical1@1 logical2@ static_choice=red,green,blue table1#variable:input_csv table2#dbfile*csv#key:dbfile output_image*pdf,png,gif,jpg
'''
import sys
from _gui import usage_gui, pd_get_dataframe, table_field

def main(*args):
    print(__name__)
    print(args)

if __name__=="__main__":
  usage_gui(__doc__)
