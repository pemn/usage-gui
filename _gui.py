#!python
# data drive GUI interface

import os, sys, re
import tkinter as tk
import tkinter.ttk as ttk
import tkinter.messagebox as messagebox
import tkinter.filedialog as filedialog
from _lib import pd_get_dataframe, table_field
import pickle
import subprocess

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
class commalist(list):
    _rowfs = ";"
    _colfs = ","
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

# detects file type and return a list of options 
class smartfilelist(object):
    # global value cache, using path as key
    cache = {}
    @staticmethod
    def smartfilelist(input_path):
        # if this file is already cached, skip to the end
        if(input_path in smartfilelist.cache):
            # do nothing
            pass
        elif(os.path.exists(input_path)):
            if(re.search("dgd\.isis$", input_path, re.IGNORECASE)):
                # list layers of dgd files
                smartfilelist.cache[input_path] = dgd_list_layers(input_path)
            elif(re.search("isis|bmf|csv|xls.?$", input_path, re.IGNORECASE)):
                # list columns of files handled by pd_get_dataframe
                smartfilelist.cache[input_path] = list(pd_get_dataframe(input_path).columns)

        else: # default to a empty list
            smartfilelist.cache[input_path] = []
    
        return(smartfilelist.cache[input_path])

class ClientScript(list):
    "Handles the script with the same name as this inteface file"
    _file = None
    _type = None
    _usage = None
    _base = os.path.splitext(sys.argv[0])[0]
    for ext in ['lava','csh','bat']:
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
        print("run")
        if cls._file is None:
            # call the main on the caller script with the arguments as a python dict
            from __main__ import main
            main(**script.get())
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
        if usage is None and cls._file is not None:
            usage = cls.parse()
        
        if usage is None or len(usage) == 0:
            r = ['arguments']
        else:
            r = usage.split()
        return(r)

    @classmethod
    def parse(cls):
        if os.path.exists(cls._file):
            with open(cls._file, 'r') as file:
                for line in file:
                    if ("usage:" in line.lower()):
                        m = re.search(r"usage:\s*\S+\s*([^\"\'\\]+)", line, re.IGNORECASE)
                        if(m):
                            cls._usage = m.group(1)
                            break
        return None

class ScriptFrame(ttk.Frame):
    "dynamic frame that holds the script argument controls"
    _usage = None
    def __init__(self, master, usage=None):
        # since tkinter classes are old style we cant use super()
        ttk.Frame.__init__(self, master)
        self._usage = usage
        
    def copy(self):
        "Assemble the current parameters and copy the full command line to the clipboard"
        #print("%s %s %s" % (ClientScript.exe(), ClientScript.file(), self.getArg()))
        cmd = "%s %s %s" % (ClientScript.exe(), ClientScript.file(), self.getArgs())
        print(cmd)
        self.clipboard_clear()
        self.clipboard_append(cmd)
        self.update()
        messagebox.showinfo(message='Command line copied to clipboard')

    def load(self, reset=False):
        for c in tuple(self.children.values()): c.destroy()
        self.arg = []
        for arg in ClientScript.args(self._usage):
            self.arg.append(re.match("\w*", arg).group(0))
            self.buildControl(arg)
        if not reset:
            # restore the settings from the last run if any
            self.set(Settings().load())

    def get(self):
        values = dict()
        for i in self.arg:
            values[i] = self.nametowidget(i).get()
        return(values)
    
    def getArgs(self):
        args = ''
        for i in self.arg:
            arg = str(self.nametowidget(i).get())
            if '"' not in arg and (' ' in arg or ';' in arg):
                arg = '"' + arg + '"'
            args += " " + arg
        return(args)
    # return [str(self.nametowidget(_).get())]
    
    def set(self, values):
        for i in values:
            if i in self.children:
                c = self.nametowidget(i)
                c.set(values[i])
                
    # override the destroy function so we can save the settings
    def destroy(self, *args):
        # store this frame settings into a ini file
        Settings().save(self.get())
        ttk.Frame.destroy(self)
        
    def buildControl(self, arg):
        m = re.match("(\w*)@", arg)
        if(m):
            CheckBox(self, m.group(1))
            return
        
        m = re.match("(\w*)\*(.+)", arg)
        if(m):
            FileEntry(self, m.group(1), m.group(2)).pack()
            return

        m = re.match("(\w*):(.+)", arg)
        if(m):
            ComboPicker(self, m.group(1), m.group(2)).pack()
            return

        m = re.match("(\w*)=(.+)", arg)
        if(m):
            ComboPicker(self, m.group(1), m.group(2)).pack()
            return

        m = re.match("(\w*)#(.+)", arg)
        if(m):
            table = tkTable(self, m.group(1))
            table.set([m.group(2).split('#')])
            return

        LabelEntry(self, arg)
    

# should behave the same as Tix LabelEntry but with some customizations
class LabelEntry(ttk.Frame):
    def __init__(self, master, label):
        # create a container frame for the combo and label
        ttk.Frame.__init__(self, master, name=label)
        ttk.Label(self, text=label).pack(side="left")
        self._control = ttk.Entry(self)
        self._control.pack(side="right")
        self.pack(fill="both", padx=20, pady=2)
        
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
        self.pack(expand=True, fill="both", padx=20, pady=2)
    
    def get(self):
        return(self._variable.get())
        
    def set(self, value):
        return(self._variable.set(value))

class LabelCombo(ttk.Frame):
    def __init__(self, master, label):
        ttk.Frame.__init__(self, master, name=label)
        ttk.Label(self, text=label).pack(side="left")
        self._control = ttk.Combobox(self)
        self._control.pack(side="right")
        self.pack(fill="both", padx=20, pady=2)
        self._control.bind("<<ComboboxSelected>>", self.ComboboxSelected)
        self._control.bind("<ButtonPress>", self.ButtonPress)

    def get(self):
        return(self._control.get())
    
    def set(self, value):
        self._control.set(value)
    
    def setValues(self, values):
        self._control['values'] = values

    # placeholder for the ComboboxSelected event handler
    def ComboboxSelected(self, *args):
        print("ComboboxSelected")
    
    # placeholder for the ButtonPress event handler
    def ButtonPress(self, *args):
        print("LabelCombo ButtonPress")

class ComboPicker(LabelCombo):
    def __init__(self, master, label, source):
        LabelCombo.__init__(self, master, label)
        self._source = source
        
    def ButtonPress(self, *args):
        print("ComboPicker ButtonPress")
        # temporarily set the cursor to a hourglass
        self._control['cursor'] = 'watch'

        if (self._source in self.master.children):
            self.setValues(smartfilelist.smartfilelist(self.master.nametowidget(self._source).get()))
        else:
            self.setValues(self._source.split(";"))
        # reset the cursor back to default
        self._control['cursor'] = ''

class FileEntry(ttk.Frame):
    "custom Entry, with label and a Browse button"
    def __init__(self, master, label, wildcard=None):
        ttk.Frame.__init__(self, master, name=label)
        ttk.Button(self, text="Browse...", command=self.OnBrowse).pack(side="right")
        self._control = ttk.Entry(self, width=40)
        self._control.pack(side="right")
        ttk.Label(self, text=label).pack(side="left")
        self.wildcard = [(_, _) for _ in wildcard.split(',')]
        self.pack(expand=True, fill="both", padx=20, pady=2)
        #~ ttk.Style().configure('style.TFrame', background='green')
        #~ self['style'] = 'style.TFrame'
    
    # activate the browse button, which shows a native fileopen dialog and sets the Entry control
    def OnBrowse(self):
        flist = filedialog.askopenfilenames(filetypes=self.wildcard + [("*", "*")])
        if(isinstance(flist, tuple)):
            self.set(",".join(flist))
    
    def get(self):
        return(self._control.get())
    
    def set(self, value):
        if(value == None or len(value) == 0):
            return
        self._control.delete(0, tk.END)
        self._control.insert(0, value)

# create a table of entry/combobox widgets
class tkTable(list, ttk.Frame):
    def __init__(self, master, name=None):
        ttk.Frame.__init__(self, master, name=name)
        list.__init__(self)
        self.configure({'borderwidth': 10, 'relief': 'groove'})
        self.pack(expand=True, fill="both", padx=20, pady=2)
        self.clear()
        
    def get(self, row=None, col=None):
        value = commalist()
        # retrieve all values as a 2d list
        if(row==None and col==None):
            value = commalist()
            for i in range(len(self)):
                value.append([self[i][j].get() for j in range(len(self[i]))])
    
        elif(row < len(self) and col < len(self[row])):
            value = self[row][col].get()
        return(value)
    
    # set the widget values, expanding the table as needed
    def set(self, data, row=None, col=0):
        if(isinstance(data, list)):
            for i in range(len(data)):
                if(isinstance(data[i], list)):
                    for j in range(len(data[i])):
                        self.set(data[i][j], i, j)
                else:
                    self.set(data[i], i)
        elif(row != None):
            # expand internal array to fit all rows and columns
            for i in range(len(self), row+1):
                self.append([])
                tk.Button(self, text="-", width=2, command=lambda: self.delRow(i)).grid(row=i, column=0, sticky="w")
                for j in range(col+1):
                    self[i].append(ttk.Combobox(self))
                    self[i][j].grid(row=i, column=j+1)
                    
            for j in range(len(self[row]),col+1):
                self[row].append(ttk.Combobox(self))
                self[row][j].grid(row=row, column=j+1)

            self[row][col].set(data)

    def addRow(self):
        self.set("", len(self), self.columnCount()-1)
    
    def delRow(self, index=0):
        buffer = self.get()
        del buffer[index]
        self.clear()
        self.set(buffer)
    
    def columnCount(self):
        if(len(self) > 0):
            return(len(self[0]))
        else:
            return(1)
    
    def clear(self):
        del self[:]
        self.append([])
        for c in tuple(self.children.values()): c.destroy()
        tk.Button(self, text="+", width=2, command=self.addRow).grid(row=99, column=0, sticky="w")
        
    def __str__(self):
        return(ttk.Frame.__str__(self))
       
# main frame
class AppTk(tk.Tk):
    "TK-Based Data driven GUI application"
    def __init__(self, usage=None):
        tk.Tk.__init__(self)
        # load the default icon if exists
        if(os.path.exists('default.ico')):
            self.iconbitmap(default='default.ico')

        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        self.createHeader()
        # create the script dynamic frame with input controls related to that scripts
        self.script = ScriptFrame(self, usage)
        self.script.grid(row=0, column=0, sticky='we')
        # build the script interface, and restore settings for any previous run
        self.script.load()
        #self.scrollY = tk.Scrollbar( self, orient=tk.VERTICAL)
        #self.scrollY.grid(row=2, column=1, sticky='ns')
        tk.Button(self, text="Run", command=self.runScript).grid(row=0, column=1, pady=20, padx=20, sticky="sew")
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
    def createHeader(self):
        # if we dont store the image in a variable, it will be garbage colected before being displayed
        canvas = tk.Canvas(self)
        # draw a Vale logo
        canvas.create_polygon(875,242, 875,242, 974,112, 974,112, 863,75, 752,112, 752,112, 500,220, 386,220, 484,757, fill="#eaab13", smooth="true")
        canvas.create_polygon(10,120, 10,120, 218,45, 554,242, 708,312, 875,242, 875,242, 484,757, 484,757, fill="#008f83", smooth="true")
        canvas['height'] = 100
        canvas['width'] = 100
        canvas.scale("all", 0, 0, 0.1, 0.1)
        canvas.grid(row=0, column=1, sticky="n")
        
        # create a combobox with all script found
        # tk.Label(self, text="Graphic User Interface for command line scripts").grid(row=0, sticky='w')
        # tk.Label(self, text=sys.argv[0]).grid(row=1, column=1)
        # ttk.Separator(self).grid(sticky='we')
            
    def runScript(self):
        print("runScript")
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
        Settings(result).save(self.script.get())

def gui(usage):
    AppTk(usage).mainloop()

# main app loop
if __name__=="__main__":
    print(__name__)
    app = AppTk()
    app.mainloop()
