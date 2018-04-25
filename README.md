# usage-gui
Data driven gui toolkit for scripts in other languages or python business logic.  
It tries to fill a role similar to other python modules like guidata and Gooey but is even simpler and with distictive features.
Another rationale for this project is that we use Tk for backend, while guidata uses Qt and Gooey uses Wx. On some builtin python environments you may have one toolkit available out of the box, and if its Tk, this project may be for you.  
May also be used to run scripts using the python bundled with the commercial software Maptek Vulcan.  

Its a pure python implementation of my similar C++ project [ScriptGui](https://github.com/pemn/ScriptGui)  

## Screenshot
![screenshot](https://github.com/pemn/usage-gui/blob/master/assets/example1os.png)

## Features
 - A graphical user interface generated from a simple one line template
 - Dynamic lists for the comboboxes. Options can be defined inline or by reading fields from csv and xlsx files.
 - Data persistence and save/load of panel settings using .ini files.
 - Copy the full script command line to clipboard, so you can run it on enviroments without a display (Ex.: telnet/ssh).
 - Single file. All resources (icon, logo, classes) are included in a single .py file (or exe if you package).
 - Adaptable branding. The icon and logo will change according to enviroment variable USERDOMAIN. Default is the Open Source logo.
 - Can be packaged into a standalone exe or called using a .cmd file from windows explorer.
 - Uses the ubiquitous and mature Tkinter (tcl/tk) for the backend rendering
 - All modules used are bundled by default on the most popular python distributions.
 - Can easily be embedded with business logic to create a single file standalone solution, even without packaging (single .py file)
 - Many quality of life smaller features like adaptive control sizes, script header display, copy command line.
 - Supported file types out of the box (more can be easily added just by editing the hardcoded list):
   - Python (.py but using the business logic main function)
   - Perl (.pl, .lava)
   - Windows Batch (.bat)
   - Unix C Shell (.csh)
   - Windows Scripting Host (.vbs, .js)
 
## How to use
### File name matters
The interface searches in the current working directory for all files that have the same base name, and are of a supported extension.
Ex.: "myscript.py" will match a file named "myscript.bat" if it exists.  
If the interface cant locate a supported file, it will run the embedded business logic, with by default is just a "print" of the arguments.  


### The `usage:` line
Once the interface finds a compatible script, it will do a text search on the contents of this file looking for the magic word: `usage:`.   
When it is found, the line containing is parsed into interface controls using the templates described below. This `usage:` can be a comment or, even better, can be the short help message describing the script expected parameters. Its common for a script to print their parameter syntax when called with a switch such as `/?` and `-h` or without any arguments. The origin of this interface was trying to "guess" a good control layout from existing usage lines. Conforming any already existing usage line to the templates should have no downsides and will even look informative.

### Control templates
- `<name>=<default value>`  
text input control with a default value in the combo box
- `<name>=<list of values separated by ,>`  
choice combo box
- `<name>*<extension>(,<extension>...)`  
file browse control, listing only files that match one of the given extensions
- `<name>:<another control name>`  
derived control that gets its list values from the file pointed by another file browse control  
different files will have different associated lists, generated on the fly  
Ex.: csv files will be a list of column names  
- `<name>@<enable/disable reach>`  
checkbox boolean control  
can be used to enable/disable groups of controls by setting the reach option to a number of following controls that will be affected
- `<name>#<control>(#<control>...)`  
grid of controls, allowing a the user to create a list of similar values  
the resulting list is semicollon separated (`;`)  
multiple controls can be used in a single line, and columns in each row will be comma (`,`) separated  
Ex.: a,1;b,2;c,3  

### Example of the "usage:" line which creates a panel like the screenshot above
`usage: $0 input_csv*csv variable_csv:input_csv some_trully_realy_long_label plain_logical@ table1#variable:input_csv enabler_logical@5 conditional_logical@ conditional_choice1=red,green,blue conditional_entry1 table2#dbfile*csv#key:dbfile output_image*pdf,png,gif,jpg out_of_reach`


## License
Apache 2.0
