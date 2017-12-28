#!python
# dummy script
'''
usage: $0 input_csv*csv variable_csv:input_csv some_trully_realy_long_label logical1@1 logical2@ static_choice=red,green,blue table1#variable:input_csv table2#dbfile*csv#key:dbfile output_image*pdf,png,gif,jpg
'''
from _gui import usage_gui

def main(*args):
  from tkinter.messagebox import showinfo
  showinfo(__file__, "Custom Business Logic for script\n" + __file__ + "\narguments:\n" + str(args))

if __name__=="__main__":
  usage_gui(__doc__)
