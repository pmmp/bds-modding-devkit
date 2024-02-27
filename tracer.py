#!/usr/bin/python3
# -*- coding: utf-8 -*-

import frida
import sys
import json
import argparse
import subprocess
import base64
import time

def validateMode(mode):
    if mode not in 'rw':
        raise argparse.ArgumentTypeError('Unknown mode')
    return mode

parser = argparse.ArgumentParser(description='bedrock_server packet tracer')
parser.add_argument('mode', help='"r" - read, "w" - write', type=validateMode)
parser.add_argument('processName', default='bedrock_server_symbols.debug')
args = parser.parse_args()
stopped = False

try:
    session = frida.attach(args.processName)
except frida.ProcessNotFoundError:
    sys.exit('Could not find bedrock_server process')
except frida.PermissionDeniedError as e:
    sys.exit(e)

logpath = './packets_' + str(time.time()) + '.txt'
logfile = open(logpath, 'wb')

def onMessage(message, data):
    if message['type'] == 'error':
        print(message['stack'])
        return
    try:
        logfile.write(str.encode(message['payload']) + b':' + base64.b64encode(data) + b'\n')
    except:
        print(message)

def onExit():
    print("Server process died!\n")
    global stopped
    stopped = True

try:
    script = session.create_script("""recv('input', function(message) {
    var mode = message.mode;
    var doRead = mode.includes('r');
    var doWrite = mode.includes('w');
    var file = message.file;
    var count = 0;
    Module.enumerateSymbols(file).forEach(function(exportedFunc) {
        if (exportedFunc.type !== 'function') {
            return;
        }
        if (!exportedFunc.name.includes('Packet')) {
            return;
        }
        if (doRead && (exportedFunc.name.endsWith('Packet4readER20ReadOnlyBinaryStream') || exportedFunc.name.endsWith('Packet5_readER20ReadOnlyBinaryStream'))) {
            console.log("Hooking function " + exportedFunc.name);
            Interceptor.attach(exportedFunc.address, {
                onEnter: function(args) {
                        //this used to be arg1, but changed to arg2 in 1.20
                        //perhaps some return-over-stack compiler optimisation generated more args?
                        this.pointer = args[2];
                },
                onLeave: function(retval) {
                        var baseAddr = Memory.readPointer(this.pointer.add(48)); //56 prior to 1.20.40 - changing to libc++ changed BinaryStream layout
                        var bufferAddr = baseAddr.add(16); //0 before 1.20.40 - strings have a different layout in libc++
                        var rlen = Memory.readULong(baseAddr.add(8));
                        var bytes = Memory.readByteArray(Memory.readPointer(bufferAddr), rlen);
                        if (bytes === null) {
                            console.log("Unexpected null payload from " + exportedFunc.name);
                        } else {
                            send('read', bytes);
                        }
                }
            });
            count++;
        }
        if (doWrite && exportedFunc.name.endsWith('Packet5writeER12BinaryStream')) {
            console.log("Hooking function " + exportedFunc.name);
            try{
            Interceptor.attach(exportedFunc.address, {
                onEnter: function(args) {
                    this.pointer = args[1];
                },
                onLeave: function(retval) {
                    var baseAddr = Memory.readPointer(this.pointer.add(48));
                    var bufferAddr = baseAddr.add(16); //0 before 1.20.40 - strings have a different layout in libc++
                    var rlen = Memory.readULong(baseAddr.add(8));
                    var bytes = Memory.readByteArray(Memory.readPointer(bufferAddr), rlen);
                    if (bytes === null) {
                        console.log("Unexpected null payload from " + exportedFunc.name);
                    } else {
                        send('write', bytes);
                    }
                }
            });
            count++;
            } catch (e) {
                console.log("Error intercepting function " + exportedFunc.name + ": " + e.toString());
            }
        }
    });
    console.log("Hooked " + count + " functions. Ready.");
});
""")

    script.on('message', onMessage)
    script.load()
    script.post({
        'type': 'input',
        'mode': args.mode,
        'file': args.processName
    })

    session.on('detached', onExit)
    while not stopped:
        time.sleep(1)
    logfile.close()

    print('Packet logs written to ' + logpath)
    print("Bye\n")
    sys.exit(0)
except KeyboardInterrupt:
    logfile.close()
    sys.exit(0)
