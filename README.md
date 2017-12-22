# usage-gui
Data driven gui toolkit for scripts in other languages or python business logic.  
It tries to fill a role similar to guidata python module but is even simpler and with distictive features, the most proeminent that it can be used with scripts in languages other than python.
Its a pure python implementation of my similar C++ project [ScriptGui](https://github.com/pemn/ScriptGui)  

## Features
 - A graphical user interface generated from a simple one line template
 - Dynamic lists for the comboboxes, capable of reading fields from csv and xlsx files.
 - Can be packaged into a exe
 - Uses the ubiquitous and mature Tkinter for the backend rendering
 - All dependencies used are bungled by default on the most popular python installations distributions.
 - Single file. All resources (icon, logo, classes) are included in a single .py file (or exe if you package).
 - Can easily be embedded with business logic to create a single file standalone solution, even without packaing (single .py file)
 - Open Source as detailed in the license
 - Flexible. Can be used with any script whose source files are ASCII files.
 - Supported file types out of the box:
   - Perl (.pl, .lava)
   - Python (.py)
   - Windows Batch (.bat, .cmd)
   - Unix C Shell (.csh)
   - Windows Scripting Host (.vbs, .js)
 
 
## Screenshot
![screenshot](https://github.com/pemn/usage-gui/blob/master/assets/example1.png)

## How to use
### File name matters
The interface searches in the current working directory for all files that have the same base name, and are of a supported extension.
Ex.: "myscript.py" will match a file named "myscript.bat" if it exists.  
If the interface cant locate a supported file, it will run the embedded business logic, with by default is just a "print" of the arguments.


### The `usage:` line
Once the interface finds a compatible script, it will do a text search on the contents of this file looking for a magic word: `usage:`  
When it is found, its line is parsed into interface controls using the templates described below. This `usage:` can be a comment or, even better, can be the short help message describing its usage. Its common for a script to print their parameter syntax when called with a switch such as `/?` and `-h` or without any arguments. The origin of this interface was trying to "guess" a good control layout from existing usage lines. Conforming any already existing usage line to the templates should have no downsides and will even look informative.

### Control templates
- `<name>=<default value>`  
text input control with a default value in the combo box
- `<name>=<list of values seprated by ,>`  
choice combo box
- `<name>*<extension>(,<extension>...)`  
file browse control, listing only files that match one of the given extensions
- `<name>:<another control name>`  
derived control that gets its list values from the file pointed by another file browse control  
different files will have differente associated lists  
Ex.: csv files will be a list of column names  
- `<name>@<default value>`  
checkbox boolean control
- `<name>#<control>(#<control>...)`  
grid of controls, allowing a the user to create a list of similar values  
the resulting list is semicollon separated (`;`)  
multiple controls can be used in a single line, and columns in each row will be comma (`,`) separated  
Ex.: a,1;b,2;c,3  

### Example of the "usage:" line which was used to create the screenshot above
`usage: $0 input_csv*csv variable_csv:input_csv some_trully_realy_long_label logical1@1 logical2@ static_choice=red,green,blue table1#variable:input_csv table2#dbfile*csv#key:dbfile output_image*pdf,png,gif,jpg`


## License
Apache 2.0
