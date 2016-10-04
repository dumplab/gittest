#!/bin/python
"""dumplab tiny REST API
========================
* provides shell access
* more to come ...

Requires:
yum install python-flask python-requests

Run this as a service:
======================
vim /etc/systemd/system/dlchfccore.service
[Unit]
Description=dumplap REST API server.
After=syslog.target network.target
After=mariadb.service

[Service]
Type=simple
ExecStart=/opt/dlchfc/bin/rest-server.py
User=root

[Install]
WantedBy=multi-user.target

systemctl enable dlchfccore.service
systemctl start dlchfccore.service && systemctl status dlchfccore.service

"""

__author__    = "dumplab"
__copyright__ = "2016 dumplab"
__license__   = "MIT"
__version__   = "0.5"
__status__    = "Development"

import cmd,os,subprocess,sys,tempfile,flask,requests

app   = flask.Flask('dumplab')
token = "dlchfc"

@app.route('/shellcmd', methods=['POST'])

def shellcmd():
        """ Execute command, return response """
        apikey = flask.request.headers.get('X-Auth-Token')
        if apikey != token:
                return "Check your auth TOKEN", 401
        else:
                print("Token ok")
        command = flask.request.json.get('command')

        if not command:
                return 400

        with tempfile.TemporaryFile() as stdout:
                status = subprocess.call(command,shell=True,stdout=stdout,stderr=subprocess.STDOUT)
                stdout.seek(0)
                output = stdout.read()

        response = {'status': status,'output': output,}
        return flask.jsonify(response)

def main():
        """ Run the web server with Python flask on tcp port 3867 (dump)"""
        app.run('127.0.0.1', port=3867, debug=True)

if __name__ == '__main__':
        main()
