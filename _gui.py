#!python
'''
Copyright 2017 Vale

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

You can contribute to the main repository at

https://github.com/pemn/usage-gui
'''
# _gui.py
# auxiliary functions for data input/output and data driven gui

### COMMON ###

import sys, os, os.path
import threading

# this function handles most of the details required when using a exe interface
def usage_gui(usage = None):
  # we already have argument, just proceed with execution
  if(len(sys.argv) > 1):
    # traps help switches: /? -? /h -h /help -help
    if(usage is not None and re.match(r'[\-/](?:\?|h|help)$', sys.argv[1])):
      print(usage)
    elif 'main' in globals():
      main(*sys.argv[1:])
    else:
      print("main() not found")
  else:
    AppTk(usage).mainloop()

# convenience function to return a dataframe base on the input file extension
# bmf: vulcan block model
# isis: vulcan database
# csv: ascii table
# xls: excel table
def pd_get_dataframe(input_path, condition = "", table_name = None, vl = None):
  import pandas as pd
  df = pd.DataFrame()
  if input_path.lower().endswith('csv'):
    df = pd.read_csv(input_path)
    if len(condition) > 0:
      df.query(condition, True)
  elif input_path.lower().endswith('bmf'):
    import vulcan
    bm = vulcan.block_model(input_path)

    # get a DataFrame with block model data
    df = bm.get_pandas(vl, bm_sanitize_condition(condition))
  elif input_path.lower().endswith('isis'):
    import vulcan
    db = vulcan.isisdb(input_path)
    # by default, use last table which is the desired one in most cases
    if table_name is None or table_name not in db.table_list():
      table_name = db.table_list()[-1]
    # create special field "KEY"
    field_list = list(db.field_list(table_name))
    fdata = []
    # db.keys is bugged as of vulcan 10.1.3
    # we can only call it once. subsequent calls will only find the last key.
    # db.rewind() does not help, and should not be necessary anyway
    for ikey in db.keys:
      for record in db.this_table(table_name):
        fdata.append([db.get_key()] + [record[field] for field in field_list])
    df = pd.DataFrame(fdata, None, ['KEY'] + field_list)
    if len(condition) > 0:
      df.query(condition, True)

  # replace -99 with NaN, meaning they will not be included in the stats
  df.mask(df == -99, inplace=True)

  return(df)


def bm_sanitize_condition(condition):
  if len(condition) > 0:

    # convert a raw condition into a actual block select string
    if re.match(r'\s*\-', condition):
      # condition is already a select syntax
      pass
    elif re.search(r'\.00t$', condition, re.IGNORECASE):
      # bounding solid
      condition = '-X -t "%s"' % (condition)
    else:
      condition = '-C "%s"' % (condition.replace('"', "'"))

  return condition

# convert field names in the TABLE:FIELD to just FIELD
def table_field(args, table=False):
  if isinstance(args, list):
    args = [table_field(arg, table) for arg in args]
  elif args.find(':') != -1:
    if table:
      args = args[0:args.find(':')]
    else:
      args = args[args.find(':')+1:]
  return(args)


## GUI ###
# data driven GUI interface

import re
import tkinter as tk
import tkinter.ttk as ttk
import tkinter.messagebox as messagebox
import tkinter.filedialog as filedialog
import pickle
import subprocess

class ClientScript(list):
  '''Handles the script with the same name as this interface file'''
  # magic signature that a script file must have for defining its gui
  _magic = r"usage:\s*\S+\s*([^\"\'\\]+)"
  _usage = None
  _file = sys.argv[0]
  _type = None
  _base = os.path.splitext(sys.argv[0])[0]
  # HARDCODED list of supporte file types
  # to add a new file type, just add it to the list
  for ext in ['csh','lava','pl','bat','vbs','js']:
    if os.path.exists(_base + '.' + ext):
      _file = _base + '.' + ext
      _type = ext.lower()
      break

  @classmethod
  def exe(cls):
    if cls._type == "csh":
      return ["csh"]
    if cls._type == "bat":
      return ["cmd", "/c"]
    if cls._type == "vbs" or cls._type == "js":
      return ["cscript", "/nologo"]
    if cls._type == "lava" or cls._type == "pl":
      return ["perl"]
    if cls._type is None:
      return ["python"]
    return []

  @classmethod
  def run(cls, script):
    if cls._type is None:
      # call the main on the caller script with the arguments as a python dict
      main(*script.get())
    else:
      # create a new process and passes the arguments on the command line
      subprocess.Popen(cls.exe() + [cls._file] + script.getArgs()).wait()

  @classmethod
  def type(cls):
    return cls._type
  
  @classmethod
  def base(cls):
    return cls._base
  
  @classmethod
  def file(cls, ext = None):
    if ext is not None:
      return cls._base + '.' + ext
    return cls._file
  
  @classmethod
  def args(cls, usage = None):
    r = []
    if usage is None and cls._type is not None:
      usage = cls.parse()

    if usage:
      m = re.search(cls._magic, usage, re.IGNORECASE)
      if(m):
        cls._usage = m.group(1)
    
    if cls._usage is None or len(cls._usage) == 0:
      r = ['arguments']
    else:
      r = cls._usage.split()
    return(r)

  @classmethod
  def fields(cls, usage = None):
    return [re.match(r"^\w+", _).group(0) for _ in cls.args(usage)]

  @classmethod
  def parse(cls):
    if os.path.exists(cls._file):
      with open(cls._file, 'r') as file:
        for line in file:
          if re.search(cls._magic, line, re.IGNORECASE):
            return(line)
    return None

  @classmethod
  def header(cls):
    r = ""
    if os.path.exists(cls._file):
      with open(cls._file, 'r') as file:
        for line in file:
          if(line.startswith('#!')):
            continue
          m = re.match(r'#\s*(.+)', line)
          if m:
            r += m.group(1) + "\n"
          else:
            break
    return r

class Settings(str):
  '''provide persistence for control values using pickled ini files'''
  _ext = '.ini'
  def __new__(cls, value=''):
    if len(value) == 0:
      value = os.path.splitext(os.path.realpath(sys.argv[0]))[0]
    if not value.endswith(cls._ext):
      value += cls._ext

    return super().__new__(cls, value)

  def save(self, obj):
    pickle.dump(obj, open(self,'wb'), -1)
    
  def load(self):
    if os.path.exists(self):
      return(pickle.load(open(self, 'rb')))
    return({})

# subclass of list with a string representation compatible to perl argument input
# which expects a comma separated list with semicolumns between rows
# this is to mantain compatibility with older versions of the usage gui
class commalist(list):
  _rowfs = ";"
  _colfs = ","
  def parse(self, arg):
    "fill this instance with data from a string"
    if isinstance(arg, str):
      for row in arg.split(self._rowfs):
        self.append(row.split(self._colfs))
    else:
      self = commalist(arg)

    return self

  def __str__(self):
    r = ""
    # custom join
    for i in self:
      if(isinstance(i, list)):
        i = self._colfs.join(i)
      if len(r) > 0:
        r += self._rowfs
      r += i
    return(r)
  def __hash__(self):
    return(len(self))

  # sometimes we have one element, but that element is ""
  # unless we override, this will evaluate as True
  def __bool__(self):
    return len(str(self)) > 0
  # compatibility if the user try to treat us as a real string
  def split(self, *args):
    return [",".join(_) for _ in self]

def dgd_list_layers(input_path):
  import vulcan
  r = []
  # return the list of layers stored in a dgd
  db = vulcan.isisdb(input_path)
  for key in db.keys:
    if db.get_key().find('$') == -1:
      r.append(db.get_key())
  return r

class smartfilelist(object):
  '''
  detects file type and return a list of relevant options
  searches are cached, so subsequent searcher for the same file path are instant
  '''
  # global value cache, using path as key
  _cache = {}
  @staticmethod
  def get(input_path):
    # if this file is already cached, skip to the end
    if(input_path in smartfilelist._cache):
      # do nothing
      pass
    elif(os.path.exists(input_path)):
      if(input_path.lower().endswith(".dgd.isis")):
        # list layers of dgd files
        smartfilelist._cache[input_path] = dgd_list_layers(input_path)
      if(input_path.lower().endswith(".bmf")):
        import vulcan
        bm = vulcan.block_model(input_path)
        smartfilelist._cache[input_path] = bm.field_list()
        bm.close()
      elif(re.search("isis|csv|xls.?$", input_path, re.IGNORECASE)):
        # list columns of files handled by pd_get_dataframe
        smartfilelist._cache[input_path] = list(pd_get_dataframe(input_path).columns)

    else: # default to a empty list
      smartfilelist._cache[input_path] = []
  
    return(smartfilelist._cache[input_path])

class UsageToken(str):
  '''handles the token format used to creating controls'''
  _name = None
  _type = None
  _data = None
  def __init__(self, arg):
    super().__init__()
    m = re.match(r"(\w*)(\*|@|#|=|:)(.*)", arg)
    if (m):
      self._name = m.group(1)
      self._type = m.group(2)
      self._data = m.group(3)
    else:
      self._name = arg
  @property
  def name(self):
    return self._name
  @property
  def type(self):
    return self._type
  @property
  def data(self):
    return self._data


class ScriptFrame(ttk.Frame):
  '''frame that holds the script argument controls'''
  _tokens = None
  def __init__(self, master, usage = None):
    ttk.Frame.__init__(self, master)

    self._tokens = [UsageToken(_) for _ in ClientScript.args(usage)]
    # for each token, create a child control of the apropriated type
    for token in self._tokens:
      c = None
      if token.type == '@':
        c = CheckBox(self, token.name, int(token.data) if token.data else 0)
      elif token.type == '*':
        c = FileEntry(self, token.name, token.data)
      elif token.type == '=':
        c = LabelCombo(self, token.name, token.data)
      elif token.type == ':':
        c = ComboPicker(self, token.name, token.data)
      elif token.type == '#':
        c = tkTable(self, token.name, token.data.split('#'))
      elif token.name:
        c = LabelEntry(self, token.name)
      else:
        continue
      c.pack(anchor="w", padx=20, pady=10, fill=tk.BOTH)
      
  def copy(self):
    "Assemble the current parameters and copy the full command line to the clipboard"
    cmd = " ".join(ClientScript.exe() + [ClientScript.file()] + self.getArgs(True))
    print(cmd)
    self.master.clipboard_clear()
    self.master.clipboard_append(cmd)
    # workaround due to tkinter clearing clipboard on exit
    messagebox.showinfo(message='Command line copied to clipboard.\nWill be cleared after interface closes.')
  
  @property
  def tokens(self):
    return self._tokens

  # get panel parameters as a list of strings
  def get(self, labels=False):
    if labels:
      return dict([[k, v.get()] for k,v in self.children.items()])
    return [self.children[t.name].get() for t in self.tokens]
  
  # get panel parameters as a flat string
  def getArgs(self, quote_blank = False):
    args = []
    for t in self.tokens:
      arg = str(self.children[t.name].get())
      if (quote_blank and len(arg) == 0) or '"' not in arg and (' ' in arg or ';' in arg):
        arg = '"' + arg + '"'
      args.append(arg)

    return(args)
  
  def set(self, values):
    if isinstance(values, dict):
      for k,v in self.children.items():
        if k in values:
          v.set(values[k])
    else:
      for i in range(len(self.tokens)):
        self.children[self.tokens[i].name].set(values[i])

class LabelEntry(ttk.Frame):
  ''' should behave the same as Tix LabelEntry but with some customizations '''
  _label = None
  _control = None
  def __init__(self, master, label):
    # create a container frame for the combo and label
    ttk.Frame.__init__(self, master, name=label)
    
    if isinstance(master, tkTable):
      self._control = ttk.Entry(self)
    else:
      #self._control = ttk.Entry(self, width=60)
      self._control = ttk.Entry(self)
      self._label = ttk.Label(self, text=label, width=-20)
      self._label.pack(side=tk.LEFT)

    self._control.pack(expand=True, fill=tk.BOTH, side=tk.RIGHT)
    
  def get(self):
    return(self._control.get())
   
  def set(self, value):
    if(value == None or len(value) == 0):
      return
    self._control.delete(0, tk.END)
    self._control.insert(0, value)

  def configure(self, **kw):
    if self._label is not None:
      self._label.configure(**kw)
    self._control.configure(**kw)
  
class CheckBox(ttk.Checkbutton):
  '''superset of checkbutton with a builtin variable'''
  def __init__(self, master, label, reach=0):
    self._variable = tk.BooleanVar()
    self._reach = reach
    ttk.Checkbutton.__init__(self, master, name=label, text=label, variable=self._variable)
    self.bind("<ButtonPress>", self.onButtonPress)
    self.bind("<Configure>", self.onButtonPress)

  def onButtonPress(self, event=None):
    if self._reach > 0:
      value = self.get()
      # invert the selection when caller is the onclick
      # because the current value is the oposite of the future value
      if int(event.type) == 4:
        value = not value
      bubble = 0
      for v in sorted(self.master.children.values(), key=tk.Misc.winfo_y):
        if(v is self):
          bubble = self._reach
        elif(bubble > 0):
          bubble -= 1
          v.configure(state = "enabled" if value else "disabled")

  def get(self):
    return(int(self._variable.get()))
    
  def set(self, value):
    #self.onButtonPress()
    return(self._variable.set(value))

class LabelCombo(ttk.Frame):
  _label = None
  _control = None
  def __init__(self, master, label, source=None):
    ttk.Frame.__init__(self, master, name=label)
    self._source = source
    if isinstance(master, tkTable):
      self._control = ttk.Combobox(self)
    else:
      self._control = ttk.Combobox(self, width=-60)
      self._label = ttk.Label(self, text=label, width=-20)
      self._label.pack(side=tk.LEFT)

    self._control.pack(expand=True, fill=tk.BOTH, side=tk.RIGHT)
    if source is not None:
      self.setValues(source.split(","))

  def get(self):
    return(self._control.get())
  
  def set(self, value):
    self._control.set(value)
  
  def setValues(self, values):
    self._control['values'] = values
    # MAGIC: if only one value in the list, use it as default
    if (len(values) == 1):
      self.set(values[0])
    # MAGIC: if any of the values is the same name as the control, select it
    for _ in values:
      if _.lower() == self.winfo_name():
        self.set(_)

  def configure(self, **kw):
    if self._label is not None:
      self._label.configure(**kw)
    self._control.configure(**kw)

class ComboPicker(LabelCombo):
  def __init__(self, master, label, source):
    LabelCombo.__init__(self, master, label)
    self._source = source
    self._control.bind("<ButtonPress>", self.onButtonPress)
    
  def onButtonPress(self, *args):
    # temporarily set the cursor to a hourglass
    self._control['cursor'] = 'watch'
    source_widget = None
    if (isinstance(self.master, tkTable)):
      if (self._source in self.master.master.children):
        source_widget = self.master.master.nametowidget(self._source)
      else:
        _,_,row = self.winfo_name().rpartition("_")
        if self._source + "_" + row in self.master.children:
          source_widget = self.master.nametowidget(self._source + "_" + row)
    elif (self._source in self.master.children):
      source_widget = self.master.nametowidget(self._source)

    if source_widget:
      self.setValues(smartfilelist.get(source_widget.get()))
    else:
      self.setValues([self._source])

    # reset the cursor back to default
    self._control['cursor'] = ''

class FileEntry(ttk.Frame):
  '''custom Entry, with label and a Browse button'''
  _label = None
  _button = None
  _control = None
  def __init__(self, master, label, wildcard=None):
    ttk.Frame.__init__(self, master, name=label)
    self._button = ttk.Button(self, text="⛘", command=self.onBrowse)
    self._button.pack(side=tk.RIGHT)
    if isinstance(master, tkTable):
      self._control = ttk.Combobox(self)
    else:
      #self._control = ttk.Combobox(self, width=60)
      self._control = ttk.Combobox(self, width=-60)
      self._label = ttk.Label(self, text=label, width=-20)
      self._label.pack(side=tk.LEFT)
    self._control.pack(expand=True, fill=tk.BOTH, side=tk.RIGHT)
    self._control.bind("<ButtonPress>", self.onButtonPress)
    self._wildcard_list = wildcard.split(',')
    self._wildcard_full = ((wildcard, ['*.' + _ for _ in self._wildcard_list]), ("*", "*"))
  
  # activate the browse button, which shows a native fileopen dialog and sets the Entry control
  def onBrowse(self):
    flist = filedialog.askopenfilenames(filetypes=self._wildcard_full)
    if(isinstance(flist, tuple)):
      slist = []
      for n in flist:
        if os.path.commonpath([n, os.getcwd()]) == os.getcwd():
          slist.append(os.path.relpath(n))
        else:
          slist.append(n)
      self.set(",".join(slist))

  def onButtonPress(self, *args):
    # temporarily set the cursor to a hourglass
    if (len(self._control['values'])):
      return

    self._control['cursor'] = 'watch'
    
    wildcard_regex = '\.(?:' + '|'.join(self._wildcard_list) + ')$'
    self._control['values'] = [_ for _ in os.listdir('.') if re.search(wildcard_regex, _)]

    # reset the cursor back to default
    self._control['cursor'] = ''

  def get(self):
    return(self._control.get())
  
  def set(self, value):
    if(value == None or len(value) == 0):
      return
    self._control.delete(0, tk.END)
    self._control.insert(0, value)

  def configure(self, **kw):
    if self._label is not None:
      self._label.configure(**kw)
    self._button.configure(**kw)
    self._control.configure(**kw)

# create a table of entry/combobox widgets
class tkTable(ttk.Labelframe):
  def __init__(self, master, label, columns):
    ttk.Labelframe.__init__(self, master, name=label, text=label)

    self._label = label
    if len(self._label) == 0:
      self._label = str(self.winfo_id())
    self._columns = [UsageToken(_) for _ in columns]
    self._cells = []
    ttk.Button(self, text="⛨", width=2, command=self.addRow).grid(row=99, column=0)
    for i in range(len(self._columns)):
      self.columnconfigure(i+1, weight=1)
      ttk.Label(self, text=self._columns[i].name).grid(row=0, column=i+1)

    self.addRow()
    # ttk.Style().configure('style.TFrame', background='green')
    # self['style'] = 'style.TFrame'
    
  # return the table data as a serialized commalist
  def get(self, row=None, col=None):
    value = ""
    # retrieve all values as a 2d list
    if(row==None and col==None):
      value = commalist()
      for i in range(len(self._cells)):
        value.append([self.get(i, j) for j in range(len(self._columns))])
  
    elif(row < len(self._cells) and col < len(self._columns)):
      value = self._cells[row][col+1].get()
    return(value)

  # set the widget values, expanding the table rows as needed
  # input data must be a string containing a serialized commalist
  def set(self, data, row=None, col=0):
    if row is None:
      data = commalist().parse(data)
      for i in range(len(data)):
        if(isinstance(data[i], list)):
          for j in range(len(data[i])):
            self.set(data[i][j], i, j)
        else:
          self.set(data[i], i)
    else:
      # expand internal array to fit the data
      for i in range(len(self._cells), row+1):
        self.addRow()
      self._cells[row][col+1].set(data)

  def addRow(self):
    row = len(self._cells)
    self._cells.append([])
    for col in range(len(self._columns)+1):
      child = None
      if col == 0:
        child = ttk.Button(self, text="⛌", width=2, command=lambda: self.delRow(row))
      else:
        token = self._columns[col-1]
        if(token.type == '@'):
          child = CheckBox(self, "%s_%s" % (token.name,row))
        elif(token.type == '*'):
          child = FileEntry(self, "%s_%s" % (token.name,row), token.data)
        elif(token.type == '='):
          child = LabelCombo(self, "%s_%s" % (token.name,row), token.data)
        elif(token.type == ':'):
          child = ComboPicker(self, "%s_%s" % (token.name,row), token.data)
        else:
          child = LabelEntry(self, "%s_%s" % (token.name,row))
      child.grid(row=row+1, column=col, sticky="we")
      self._cells[row].append(child)
  
  def delRow(self, index=0):
    buffer = self.get()
    del buffer[index]
    self.clear()
    self.set(buffer)
  
  def clear(self):
    for i in range(len(self._cells)-1,-1,-1):
      for j in range(len(self._cells[i])-1,-1,-1):
        self._cells[i][j].destroy()
    del self._cells[:]

  def configure(self, **kw):
    if "state" in kw:
      for v in self.children.values():
        v.configure(**kw)
    else:
      super().configure(**kw)

# main frame
class AppTk(tk.Tk):
  '''TK-Based Data driven GUI application'''
  _iconfile_name = None
  def __init__(self, usage=None):
    root = tk.Tk.__init__(self)
    self.title(ClientScript._base)
    
    self._iconfile_name = self.default_ico()
    self.iconbitmap(default=self._iconfile_name)

    self.columnconfigure(0, weight=1)

    self.canvas = tk.Canvas(root, width=self.winfo_screenwidth() * 0.35)
    self.script = ScriptFrame(self.canvas, usage)
    self.vsb = ttk.Scrollbar(root, orient="vertical", command=self.canvas.yview)
    self.canvas.configure(yscrollcommand=self.vsb.set)

    self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    self.canvas_frame = self.canvas.create_window((0,0), window=self.script, anchor="nw")

    self.vsb.pack(side=tk.LEFT, fill=tk.Y)
    self.script.bind("<Configure>", self.onFrameConfigure)
    self.canvas.bind('<Configure>', self.onCanvasConfigure)

    ttk.Label(self, text=ClientScript.header()).pack(side=tk.BOTTOM)
    
    # if we dont store the image in a variable, it will be garbage colected before being displayed
    self.drawLogo().pack(side=tk.TOP, anchor="ne")
    self.button = ttk.Button(self, text="Run ✅", command=self.runScript)
    self.button.pack(side=tk.LEFT)
    
    self.progress = ttk.Progressbar(self, mode="determinate")
    self.progress.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=10)

    self.createMenu()
    self.script.set(Settings().load())

  def onCanvasConfigure(self, event):
    self.canvas.itemconfig(self.canvas_frame, width = event.width - 4)

  def onFrameConfigure(self, event):
    '''Reset the scroll region to encompass the inner frame'''
    self.canvas.configure(scrollregion=self.canvas.bbox("all"))
    self.canvas['height'] = min(self.winfo_screenheight() * 0.8, self.script.winfo_reqheight())

  def createMenu(self):
    '''create a hardcoded menu for our app'''
    # disable a legacy option to detach menus
    self.option_add('*tearOff', False)
    menubar = tk.Menu(self)
    menu_file = tk.Menu(menubar)
    menu_edit = tk.Menu(menubar)
    menu_help = tk.Menu(menubar)
    menubar.add_cascade(menu=menu_file, label='File')
    menubar.add_cascade(menu=menu_help, label='Help')
    menu_file.add_command(label='Copy Command Line', command=self.script.copy)
    menu_file.add_command(label='Open Settings', command=self.openSettings)
    menu_file.add_command(label='Save Settings', command=self.saveSettings)
    menu_file.add_command(label='Exit', command=self.destroy)
    menu_help.add_command(label='Help...', command=self.showHelp)
    menu_help.add_command(label='About...', command=self.showAbout)
    self['menu'] = menubar
      
  def runScript(self):
    # run the process in another thread as not to block the GUI message loop
    def fork():
      self.progress.configure(value = 0, mode = "indeterminate")
      self.progress.start()
      self.button.configure(state = "disabled", text = "Run ⮔")
      try:
        ClientScript.run(self.script)
        self.button.configure(text = "Run ✔")
        self.progress.stop()
        self.progress.configure(value = 100)
      except Exception as e:
        self.button.configure(text = "Run ☠")
        self.progress.stop()
        messagebox.showerror(message=e,title=sys.argv[0])
      finally:
        self.button.configure(state = "enabled")
        self.progress.configure(mode = "determinate")

    threading.Thread(None, fork).start()

  def showHelp(self):
    script_pdf = ClientScript.file('pdf')
    if os.path.exists(script_pdf):
      os.system(script_pdf)
    else:
      messagebox.showerror(message='Help file not found',title='Help')
    
  def showAbout(self):
    messagebox.showinfo(message='Graphic User Interface to command line scripts',title='About')

  def openSettings(self):
    result = filedialog.askopenfilename(filetypes=[("ini", "*.ini")])
    if len(result) == 0:
      return
    self.script.set(Settings(result).load())
    
  def saveSettings(self):
    result = filedialog.asksaveasfilename(filetypes=[("ini", "*.ini")])
    if len(result) == 0:
      return
    Settings(result).save(self.script.get(True))
  
  def destroy(self):
    Settings().save(self.script.get(True))
    os.remove(self._iconfile_name)
    tk.Tk.destroy(self)

  def drawLogo(self):
    '''draw a custom logo that will fit the ne corner of our app'''
    canvas = tk.Canvas(self)
    canvas.create_polygon(875,242, 875,242, 974,112, 974,112, 863,75, 752,112, 752,112, 500,220, 386,220, 484,757, fill="#eaab13", smooth="true")
    canvas.create_polygon(10,120, 10,120, 218,45, 554,242, 708,312, 875,242, 875,242, 484,757, 484,757, fill="#008f83", smooth="true")
    canvas['height'] = 100
    canvas['width'] = 100
    canvas.scale("all", 0, 0, 0.1, 0.1)
    return canvas

  def default_ico(self):
    import tempfile, binascii
    iconhexdata = \
    '0000010001002020000001002000a8100000160000002800000020000000' \
    '400000000100200000000000000000000000000000000000000000000000' \
    '0000ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00' \
    'ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffff' \
    'ff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00' \
    'ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffff' \
    'ff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00' \
    'ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffff' \
    'ff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00' \
    'ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffff' \
    'ff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00' \
    'ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffff' \
    'ff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00' \
    'ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffff' \
    'ff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00' \
    'ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffff' \
    'ff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00' \
    'ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffff' \
    'ff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00' \
    'ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffff' \
    'ff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00' \
    'ffffff00848f005b83920023ffffff00ffffff00ffffff00ffffff00ffff' \
    'ff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00' \
    'ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffff' \
    'ff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00' \
    'ffffff00ffffff00828e002d838f00f6838f00cd92920007ffffff00ffff' \
    'ff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00' \
    'ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffff' \
    'ff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00' \
    'ffffff00ffffff00ffffff008b8b000b829000d7838f00ff838f00ff8490' \
    '0095ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00' \
    'ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffff' \
    'ff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00' \
    'ffffff00ffffff00ffffff00ffffff00ffffff00838e00a3838f00ff838f' \
    '00ff838f00ff838f00ff828e0056ffffff00ffffff00ffffff00ffffff00' \
    'ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffff' \
    'ff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00' \
    'ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00828f0062838f' \
    '00ff838f00ff838f00ff838f00ff838f00ff838f00f1808e0024ffffff00' \
    'ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffff' \
    'ff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00' \
    'ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff008591' \
    '002c838f00f6838f00ff838f00ff838f00ff838f00ff838f00ff838f00ff' \
    '838f00cf92920007ffffff00ffffff00ffffff00ffffff00ffffff00ffff' \
    'ff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00' \
    'ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffff' \
    'ff008b8b000b838f00d6838f00ff838f00ff838f00ff838f00ff838f00ff' \
    '838f00ff838f00ff838f00ff84900097ffffff00ffffff00ffffff00ffff' \
    'ff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00' \
    'ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffff' \
    'ff00ffffff00ffffff00838f00a1838f00ff838f00ff838f00ff838f00ff' \
    '838f00ff838f00ff838f00ff838f00ff838f00ff838f00ff828e0058ffff' \
    'ff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00' \
    'ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffff' \
    'ff00ffffff00ffffff00ffffff00838e0061838f00ff838f00ff838f00ff' \
    '838f00ff838f00ff838f00ff838f00ff838f00ff838f00ff838f00ff838f' \
    '00ff838f00f2868d0026ffffff00ffffff00ffffff00ffffff00ffffff00' \
    'ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffff' \
    'ff00ffffff00ffffff00ffffff00ffffff00828e002b838f00f5838f00ff' \
    '838f00ff838f00ff838f00ff838f00ff838f00ff838f00ff838f00ff838f' \
    '00ff838f00ff838f00ff838f00ff838f00d080800008ffffff00ffffff00' \
    'ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffff' \
    'ff00ffffff00ffffff00ffffff00ffffff00ffffff008099000a838f00d6' \
    '838f00ff838f00ff838f00ff838f00ff838f00ff838f00ff838f00ff838f' \
    '00ff838f00ff838f00ff838f00ff838f00ff838f00ff838f00ff838e009a' \
    'ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffff' \
    'ff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00' \
    '838f00a0838f00ff838f00ff838f00ff838f00ff838f00ff838f00ff838f' \
    '00ff838f00ff838f00ff838f00ff838f00ff838f00ff838f00ff838f00ff' \
    '838f00ff838f00ff828e005affffff00ffffff00ffffff00ffffff00ffff' \
    'ff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00' \
    'ffffff00828f0060838f00ff838f00ff838f00ff838f00ff838f00ff838f' \
    '00ff838f00ff838f00ff838f00ff838f00ff838f00ff838f00ff838f00ff' \
    '838f00ff838f00ff838f00ff838f00ff838f00f383900027ffffff00ffff' \
    'ff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00' \
    'ffffff00ffffff008692002a838f00f5838f00ff838f00ff838f00ff838f' \
    '00ff838f00ff838f00ff838f00ff838f00ff838f00ff838f00ff838f00ff' \
    '838f00ff838f00ff838f00ff838f00ff838f00ff838f00ff838f00ff838f' \
    '00d28e8e0009ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00' \
    'ffffff00ffffff00ffffff008099000a828e00d5838f00ff838f00ff838f' \
    '00ff838f00ff838f00ff838f00ff838f00ff838f00ff838f00ff838f00ff' \
    '838f00ff838f00ff838f00ff838f00ff838f00ff838f00ff838f00ff838f' \
    '01fe838f00ff838f00ff838e009cffffff00ffffff00ffffff00ffffff00' \
    'ffffff00ffffff00ffffff00ffffff00ffffff00848f009f838f00ff838f' \
    '00ff838f00ff838f00ff838f00ff838f00ff838f00ff838f00ff838f00ff' \
    '838f00ff838f00ff838f00ff838f00ff838f00ff838f00ff629746d032a3' \
    'aac016aae3de14abeaf817aae2de22a7caca5e984bd08290005cffffff00' \
    'ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00848e005f838f' \
    '00ff838f00ff838f00ff838f00ff838f00ff838f00ff838f00ff838f00ff' \
    '838f00ff838f00ff838f00ff838f00ff838f00ff838f00ff7b9110f021a8' \
    'ccc713abeaff13abeaff13abeaff13abeaff13abeaff13abeaff13abeaff' \
    '1da9d5c75c964e27ffffff00ffffff00ffffff00ffffff00ffffff008692' \
    '002a838f00f5838f00ff838f00ff838f00ff838f00ff838f00ff838f00ff' \
    '838f00ff838f00ff838f00ff838f00ff838f00ff838f00ff838f00ff6796' \
    '3bd515aae6e213abeaff13abeaff13abeaff13abeaff13abeaff13abeaff' \
    '13abeaff13abeaff13abeaff14abe9cf1ab3e60affffff00ffffff00ffff' \
    'ff008099000a838f00d4838f00ff838f00ff838f00ff838f00ff838f00ff' \
    '838f00ff838f00ff838f00ff838f00ff838f00ff838f00ff838f00ff838f' \
    '00ff848f00991ca7d53713acea8713acead913abeaff13abeaff13abeaff' \
    '13abeaff13abeaff13abeaff13abeaff13abeaff13abeaff13aceba2ffff' \
    'ff00ffffff00ffffff008390009e838f00ff838f00ff838f00ff838f00ff' \
    '838f00ff838f00ff838f00ff838f00ff838f00ff838f00ff838f00ff838f' \
    '00ff838f00fa828e0068ffffff00ffffff00ffffff00ffffff0014aaeb33' \
    '13abeabf13abeaff13abeaff13abeaff13abeaff13abeaff13abeaff13ab' \
    'eaff13abeaff14aaeb66ffffff008290005e838f00ff838f00ff838f00ff' \
    '838f00ff838f00ff838f00ff838f00ff838f00ff838f00ff838f00ff838f' \
    '00ff838f00ff838f00e88491003cffffff00ffffff00ffffff00ffffff00' \
    'ffffff00ffffff00ffffff0013aae95112abeadd13abeaff13abeaff13ab' \
    'eaff13abeaff13abeaff13abeaff13abeaf715acea31838e00a3838f00ff' \
    '838f00ff838f00ff838f00ff838f00ff838f00ff838f00ff838f00ff838f' \
    '00ff838f00ff838f00ff838f00cb8092001cffffff00ffffff00ffffff00' \
    'ffffff00ffffff00ffffff00ffffff00ffffff00ffffff0000aaff0614ab' \
    'eb7313abeaef13abeaff13abeaff13abeaff13abeaff13abeaff13aaebbb' \
    'ffffff00848f005b828f00d9838f00ff838f00ff838f00ff838f00ff838f' \
    '00ff838f00ff838f00ff838f00e0838e0061aaaa0003ffffff00ffffff00' \
    'ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffff' \
    'ff00ffffff00ffffff000eaaf11214aaeb5a13abeb9713abebc812abe99a' \
    '14abeb581caae309ffffff00ffffff00ffffff00828e003d838f0080838f' \
    '00a1838f00c2838e00b3838f00848490005380800006ffffff00ffffff00' \
    'ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffff' \
    'ff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00' \
    'ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffff' \
    'ff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00' \
    'ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffff' \
    'ff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00' \
    'ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffff' \
    'ff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00' \
    'ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffff' \
    'ff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00' \
    'ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffff' \
    'ff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00' \
    'ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffff' \
    'ff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00' \
    'ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffff' \
    'ff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00' \
    'ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffff' \
    'ff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00' \
    'ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffff' \
    'ff00ffffff00ffffff00ffffff00ffffff00ffffffffffffffffffffffff' \
    'fffffffffffffffffffe7ffffffc3ffffff83ffffff81ffffff00fffffe0' \
    '07ffffc007ffffc003ffff8001ffff0000fffe0000fffe00007ffc00003f' \
    'f800001ff000001ff000000fe0000007c00040038001f8038003fe010007' \
    'ff80c01fffe3f07fffffffffffffffffffffffffffffffffffff'
    # create temp icon file, will be cleaned by tk.Tk destroy
    iconfile = tempfile.NamedTemporaryFile(delete=False)
    iconfile.write(binascii.a2b_hex(iconhexdata))
    return iconfile.name

# default main for when this script is standalone
# when this as a library, will redirect to the caller script main()
def main(*args):
  if (__name__ != '__main__'):
    from __main__ import main
    # redirect to caller script main
    main(*args)
    return
  # run standalone main code
  print(__name__)
  print(args)
  messagebox.showinfo(message='Business Logic placeholder')
