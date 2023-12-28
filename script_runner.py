#!python
# proof of concept self contained web interface for python scripts

# python script_runner.py http_server='0.0.0.0' http_port=5000
# python script_runner.py port=5000


import sys, os, os.path, webview
from glob import glob
from win32api import GetSystemMetrics
from zipfile import ZipFile
from flask import request, Flask, Response, send_file, redirect, render_template, render_template_string
import subprocess

class FlaskApp(Flask):
  _zfn = os.path.splitext(sys.argv[0])[0] + '.pyz'
  _zfo = None
  def __init__(self):
    # (import_name, static_path=None, static_url_path=None, static_folder='static', template_folder='templates', instance_path=None, instance_relative_config=False, root_path=None)
    super().__init__(__name__, static_folder=None, template_folder='')
    if os.path.exists(self._zfn):
      self._zfo = ZipFile(self._zfn, 'r')
    else:
      print(self._zfn,"not found!")

    @self.route('/')
    def _root():
      return render_template_string('''
      <!DOCTYPE html>
      <html>
        <head>
          <link rel="stylesheet" href="milligram.css" />
        </head>
        <body>
          📂<br/>
          <div style="padding-left: 1em">
          {% for item in items %}
            📄<a href="/form/{{ item }}">{{ item }}</a><br/>
          {% endfor %}
          </div>
          <br/>
          🚧<a href="debug1.html">debug1.html</a><br/>
        </body>
      </html>''', items=glob('*.py'))

    @self.route('/<path:p>')
    def _file(p):
      f = None
      if os.path.exists(p):
        print('<fs> /',p)
        f = p
      elif self._zfo is None:
        return Response(None, 500)
      elif p not in self._zfo.namelist():
        return Response(None, 404)
      else:
        print(self._zfn,'/',p)
        f = self._zfo.open(p)
      return send_file(f, download_name=os.path.basename(p))
    
    @self.route('/info/<path:p>')
    def _info(p):
      from _gui import ClientScript
      ClientScript(p)
      return render_template_string('''
      <!DOCTYPE html>
      <html>
        <head>
          <link rel="stylesheet" href="milligram.css" />
        </head>
        <body>
          <button onclick="history.back()">🔙</button>
          <br/>
          <br/>
          <br/>
          🐍{{ p }}
          <br/>
          {% for item in items %}
            ✏️{{ item }}<br/>
          {% endfor %}
        </body>
      </html>''', p=p, items=ClientScript.singleton.args())
    
    @self.route('/form/<path:p>', methods=['GET', 'POST'])
    def _form(p):
      print(f'path {request.path} method {request.method}')
      from _gui import ClientScript, UsageToken
      ClientScript(p)
      if request.method == 'GET':
        print(ClientScript.singleton.args())
        print(__name__)
        print(ClientScript.singleton.type)
        print(ClientScript.singleton._usage)
        fields = [UsageToken(_).json for _ in ClientScript.singleton.args()]
        print(p)
        print(fields)
        return render_template('json_form.html', url=request.path, name=os.path.splitext(p)[0], fields=fields)
      if request.method == 'POST':
        args = ClientScript.singleton.exe + [ClientScript.singleton.file()] + ClientScript.singleton.get(request.json.get('record'))
        print(*args)
        p = subprocess.Popen(" ".join(args))
        p.wait()
        returncode = p.returncode
        #returncode = 'ok'
        return {"error": False, "text": f"returncode={returncode}"}

    
    @self.route('/echo', methods=['GET', 'POST', 'PUT'])
    def _echo():
      print(f'path {request.path} method {request.method}')
      print(request.headers)
      # print(len(request.files))
      if request.mimetype.endswith('json'):
        print(request.json)
      else:
        print(request.stream.read())
      return Response(None, 204)

  def file_read(self, fp):
    if os.path.exists(fp):
      print("<fs> /",fp)
      return open(fp).read()
    if self._zfo is None:
      if os.path.exists(self._zfn):
        self._zfo = ZipFile(self._zfn, 'r')
    if self._zfo and fp in self._zfo.namelist():
      print(self._zfn,'/',fp)
      return self._zfo.open(fp).read().decode()
    return ''

class PyApi(object):
  _wn = None
  def __call__(self, window = None):
    self._wn = window
    for a in dir(self):
      if not a.startswith('_'):
        m = getattr(self, a)
        if callable(m):
          window.expose(m)

    #window.evaluate_js("document.forms[0].path_to_site.value = '/teams/portaldipf'")

  def echo(self, data = None):
    print("echo")
    print(data)

  def submit(self, data = None):
    print("submit")
    print(data)


def main(kwargs):
  #create_window(title, url, html, js_api, width, height, x, y, screen, resizable, fullscreen, min_size, hidden, frameless, easy_drag, focus, minimized, maximized, on_top, confirm_close, background_color, transparent, text_select, zoomable, draggable, server, server_args, localization)
  app = FlaskApp()
  if 'port' in kwargs:
    app.run(**kwargs)
    return
  # GetSystemMetrics(16) * 3 // 4, GetSystemMetrics(17) * 3 // 4
  w = webview.create_window(None, FlaskApp(), None, None, *map(GetSystemMetrics, (16,17)))

  #start(func, args, localization, gui, debug, http_server, http_port, user_agent, private_mode, storage_path, menu, server, server_args, ssl)
  webview.start(PyApi(), w, **kwargs)

def parse_kwargs(argv):
  return dict([(_[0], eval(_[2])) for _ in [str.partition(_, '=') for _ in argv[1:]]])

if __name__ == '__main__':
  main(parse_kwargs(sys.argv))
