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
    logfile.write(str.encode(message['payload']) + b':' + base64.b64encode(data) + b'\n')

def onExit():
    print("Server process died!\n")
    global stopped
    stopped = True

try:
    script = session.create_script("""var stringLength = new NativeFunction(Module.findExportByName(null, '_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE6lengthEv'), 'long', ['pointer']);

recv('input', function(message) {
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
                        this.pointer = args[1];
                },
                onLeave: function(retval) {
                        var realAddr = Memory.readPointer(this.pointer.add(56));
                        var rlen = stringLength(realAddr);
                        send('read', Memory.readByteArray(Memory.readPointer(realAddr), rlen));
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
                    var realAddr = Memory.readPointer(this.pointer.add(56));
                    var rlen = stringLength(realAddr);
                    send('write', Memory.readByteArray(Memory.readPointer(realAddr), rlen));
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
    print('Logging packets to ' + logpath)
    while not stopped:
        time.sleep(1)
    logfile.close()
    print("Bye\n")
    sys.exit(0)
except KeyboardInterrupt:
    logfile.close()
    sys.exit(0)
