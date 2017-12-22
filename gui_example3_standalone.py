#!python
from _gui import usage_gui

def main(*args):
  from tkinter.messagebox import showinfo
  showinfo(__file__, "Custom Business Logic for script\n" + __file__ + "\narguments:\n" + str(args))

if __name__=="__main__":
  usage_gui("usage: script.py input*csv field:input choice=good,bad,ugly output*pdf,png")
