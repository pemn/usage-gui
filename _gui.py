#!python
"""
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
"""
# _gui.py
# auxiliary functions for data input/output and data driven gui

### COMMON ###

import sys, os, os.path

# this function handles most of the details required when using a exe interface
def usage_gui(usage = None):
  # we already have argument, just proceed with execution
  if(len(sys.argv) > 1):
    # traps help switches: /? -? /h -h /help -help
    if(usage is not None and re.match(r'[\-/](?:\?|h|help)$', sys.argv[1])):
      print(usage)
    elif 'main' in locals():
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

    if len(condition) > 0:
      condition = '-C "%s"' % (condition)

    # get a DataFrame with block model data
    df = bm.get_pandas(vl, condition)
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
    "Handles the script with the same name as this interface file"
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
        if cls._type == "lava":
            return "perl"
        if cls._type == "csh":
            return "csh"
        if cls._type == "bat":
            return "cmd"
        if cls._type is None:
            return "python"
        return None

    @classmethod
    def run(cls, script):
        if cls._type is None:
            # call the main on the caller script with the arguments as a python dict
            main(*script.get())
        else:
            # create a new process and passes the arguments on the command line
            #process = subprocess.Popen(argv, 0, None, subprocess.PIPE, subprocess.PIPE, subprocess.PIPE)
            process = subprocess.Popen([cls.exe(), cls._file, script.getArgs()])

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


class Settings(str):
    "provide persistence for control values using pickled ini files"
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
        for row in arg.split(self._rowfs):
            self.append(row.split(self._colfs))
        return self

    def __str__(self):
        r = None
        for i in self:
            if(isinstance(i, list)):
                i = self._colfs.join(i)
            if(r == None):
                r = i
            else:
                r += self._rowfs + i
        return(r)
    def __hash__(self):
        return(len(self))

def dgd_list_layers(input_path):
    import vulcan
    r = []
    # return the list of layers stored in a dgd
    db = vulcan.isisdb(input_path)
    for key in db.keys:
        if db.get_key().find('$') == -1:
            r.append(db.get_key())
    return r

# detects file type and return a list of relevant options
# searches are cached, so subsequent searcher for the same file path are instant
class smartfilelist(object):
    # global value cache, using path as key
    _cache = {}
    @staticmethod
    def get(input_path):
        # if this file is already cached, skip to the end
        if(input_path in smartfilelist._cache):
            # do nothing
            pass
        elif(os.path.exists(input_path)):
            if(re.search("dgd\.isis$", input_path, re.IGNORECASE)):
                # list layers of dgd files
                smartfilelist._cache[input_path] = dgd_list_layers(input_path)
            elif(re.search("isis|bmf|csv|xls.?$", input_path, re.IGNORECASE)):
                # list columns of files handled by pd_get_dataframe
                smartfilelist._cache[input_path] = list(pd_get_dataframe(input_path).columns)

        else: # default to a empty list
            smartfilelist._cache[input_path] = []
    
        return(smartfilelist._cache[input_path])

class UsageToken(str):
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

class ScriptFrame(list):
    "virtual frame that holds the script argument controls"
    _usage = None
    _master = None
    def __init__(self, master, usage = None):
        self._master = master
        self._tokens = [UsageToken(_) for _ in ClientScript.args(usage)]
        for i in range(len(self._tokens)):
            self.append(self.buildControl(self._tokens[i]))
            self[-1].grid(pady=10, padx=20, row=i, sticky="we")
            

    @property
    def master(self):
        return self._master

    def copy(self):
        "Assemble the current parameters and copy the full command line to the clipboard"
        cmd = "%s %s %s" % (ClientScript.exe(), ClientScript.file(), self.getArgs())
        print(cmd)
        self.master.clipboard_clear()
        self.master.clipboard_append(cmd)
        self.master.update()
        messagebox.showinfo(message='Command line copied to clipboard')

    def children(self):
        return self

    def get(self, labels=False):
        if labels:
            return dict([[_.winfo_name(), _.get()] for _ in self])
        return [_.get() for _ in self]
    
    def getArgs(self):
        args = ''
        for n in self:
            arg = str(n.get())
            if len(arg) == 0 or '"' not in arg and (' ' in arg or ';' in arg):
                arg = '"' + arg + '"'
            args += " " + arg
        return(args)
    
    def set(self, values):
        if isinstance(values, dict):
            for n in self:
                k = n.winfo_name()
                if k in values:
                    n.set(values[k])
        else:
            for i in range(min(len(self), len(values))):
                self[i].set(values[i])

    def buildControl(self, token):
        result = None
        if(token.type == '@'):
            result = CheckBox(self.master, token.name, bool(token.data))
        elif(token.type == '*'):
            result = FileEntry(self.master, token.name, token.data)
        elif(token.type == '='):
            result = LabelCombo(self.master, token.name, token.data)
        elif(token.type == ':'):
            result = ComboPicker(self.master, token.name, token.data)
        elif(token.type == '#'):
            result = tkTable(self.master, token.name, token.data.split('#'))
        else:
            result = LabelEntry(self.master, token.name)
        return result
        

# should behave the same as Tix LabelEntry but with some customizations
class LabelEntry(ttk.Frame):
    def __init__(self, master, label):
        # create a container frame for the combo and label
        ttk.Frame.__init__(self, master, name=label)
        
        if isinstance(master, tkTable):
            self._control = ttk.Entry(self)
        else:
            self._control = ttk.Entry(self, width=60)
            ttk.Label(self, text=label, width=-20).pack(side="left")

        self._control.pack(expand=True, fill="both", side="right")
        
    def get(self):
        return(self._control.get())
   
    def set(self, value):
        if(value == None or len(value) == 0):
            return
        self._control.delete(0, tk.END)
        self._control.insert(0, value)
    

class CheckBox(ttk.Checkbutton):
    "superset of checkbutton with a builtin variable"
    def __init__(self, master, label, start=False):
        self._variable = tk.BooleanVar(value=start)
        ttk.Checkbutton.__init__(self, master, name=label, text=label, variable=self._variable)
    
    def get(self):
        return(int(self._variable.get()))
        
    def set(self, value):
        return(self._variable.set(value))

class LabelCombo(ttk.Frame):
    def __init__(self, master, label, source=None):
        ttk.Frame.__init__(self, master, name=label)
        self._source = source
        if isinstance(master, tkTable):
            self._control = ttk.Combobox(self)
        else:
            self._control = ttk.Combobox(self, width=60)
            ttk.Label(self, text=label, width=-20).pack(side="left")

        self._control.pack(expand=True, fill="both", side="right")
        self._control.bind("<ButtonPress>", self.ButtonPress)

    def get(self):
        return(self._control.get())
    
    def set(self, value):
        self._control.set(value)
    
    def setValues(self, values):
        self._control['values'] = values
    
    # placeholder for the ButtonPress event handler
    def ButtonPress(self, *args):
        if self._source is not None:
            self.setValues(self._source.split(","))

class ComboPicker(LabelCombo):
    def __init__(self, master, label, source):
        LabelCombo.__init__(self, master, label, source)
        self._source = source
        
    def ButtonPress(self, *args):
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
    "custom Entry, with label and a Browse button"
    def __init__(self, master, label, wildcard=None):
        ttk.Frame.__init__(self, master, name=label)
        ttk.Button(self, text="⛘", command=self.OnBrowse).pack(side="right")
        if isinstance(master, tkTable):
            self._control = ttk.Entry(self)
        else:
            self._control = ttk.Entry(self, width=60)
            ttk.Label(self, text=label, width=-20).pack(side="left")
        self._control.pack(expand=True, fill="both", side="right")
        self.wildcard = [[wildcard, ['*.' + _ for _ in wildcard.split(',')]]]
    
    # activate the browse button, which shows a native fileopen dialog and sets the Entry control
    def OnBrowse(self):
        flist = filedialog.askopenfilenames(filetypes=self.wildcard + [("*", "*")])
        if(isinstance(flist, tuple)):
            slist = []
            for n in flist:
                if os.path.commonpath([n, os.getcwd()]) == os.getcwd():
                    slist.append(os.path.relpath(n))
                else:
                    slist.append(n)
            self.set(",".join(slist))
    
    def get(self):
        return(self._control.get())
    
    def set(self, value):
        if(value == None or len(value) == 0):
            return
        self._control.delete(0, tk.END)
        self._control.insert(0, value)

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
        value = None
        # retrieve all values as a 2d list
        if(row==None and col==None):
            value = commalist()
            for i in range(len(self._cells)):
                value.append([self.get(i, j) for j in range(len(self._columns))])
    
        elif(row < len(self._cells) and col < len(self._columns)):
            value = self._cells[row][col+1].get()
        return(str(value))

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
                    child = CheckBox(self, "%s_%s" % (token.name,row), bool(token.data))
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

def default_ico():
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

# main frame
class AppTk(tk.Tk):
    "TK-Based Data driven GUI application"
    _iconfile_name = default_ico()
    def __init__(self, usage=None):
        tk.Tk.__init__(self)
        self.title(ClientScript._base)
        
        self.iconbitmap(default=self._iconfile_name)

        # self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        # create the script virtual frame with input controls related to that scripts
        self.getLogo().grid(row=0, column=1, rowspan=3)
        ttk.Button(self, text="Run", command=self.runScript).grid(row=2, column=1, rowspan=3, pady=20, padx=20)
        self.script = ScriptFrame(self, usage)
        self.script.set(Settings().load())

        # build the script interface, and restore settings for any previous run
        #self.scrollY = tk.Scrollbar( self, orient=tk.VERTICAL)
        #self.scrollY.grid(row=2, column=1, sticky='ns')
        self.createMenu()

    def createMenu(self):
        # disable a legacy option to detach menus
        self.option_add('*tearOff', False)
        menubar = tk.Menu(self)
        self['menu'] = menubar
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

    # custom function to populate the widgets for this application
    def getLogo(self):
        # if we dont store the image in a variable, it will be garbage colected before being displayed
        canvas = tk.Canvas(self)
        # draw a Vale logo
        canvas.create_polygon(875,242, 875,242, 974,112, 974,112, 863,75, 752,112, 752,112, 500,220, 386,220, 484,757, fill="#eaab13", smooth="true")
        canvas.create_polygon(10,120, 10,120, 218,45, 554,242, 708,312, 875,242, 875,242, 484,757, 484,757, fill="#008f83", smooth="true")
        canvas['height'] = 100
        canvas['width'] = 100
        canvas.scale("all", 0, 0, 0.1, 0.1)
        return canvas
            
    def runScript(self):
        ClientScript.run(self.script)

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


if __name__=="__main__":
  usage_gui(None)
