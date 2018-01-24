#!python
# sample script for the _gui.py data-driven GUI
# contains all the features and is also used as a test
# this text is stored in the header of the client script
# v1.3 02/2017 developer A
# v1.2 11/2016 developer B
# v1.1 08/2015 developer A
# v1.0 01/2015 original creator
'''
usage: $0 input_csv*csv variable_csv:input_csv some_trully_realy_long_label plain_logical@ table1#variable:input_csv enabler_logical@5 conditional_logical@ conditional_choice1=red,green,blue conditional_entry1 table2#dbfile*csv#key:dbfile output_image*pdf,png,gif,jpg out_of_reach
'''
from _gui import usage_gui

def main(*args):
  from tkinter.messagebox import showinfo
  showinfo(__file__, "Custom Business Logic for script\n" + __file__ + "\narguments:\n" + str(args))

if __name__=="__main__":
  usage_gui(__doc__)
