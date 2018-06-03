'use strict';

const AF_INET = 2;
const AF_INET6 = 30;
const ECONNREFUSED = 111;


const connect = new NativeFunction(
    Module.findExportByName(null, "connect"),
    'int', ['int', 'pointer', 'int']);

    
const htons = new NativeFunction(
    Module.findExportByName(null, "htons"),
    "uint16", ["uint16"]);

Interceptor.replace(connect, new NativeCallback(function(socket, address, addressLen) {
    const family = Memory.readU8(address);
    if (family == AF_INET || family == AF_INET6) {
        const port = (Memory.readU8(address.add(2)) << 8) | Memory.readU8(address.add(3));
        var ip = '';
        if (family == AF_INET) {
            for (var offset = 4; offset != 8; offset++) {
                if (ip.length > 0)
                    ip += '.';
                ip += Memory.readU8(address.add(offset));
            }
        } else {
            for (var offset = 8; offset !== 24; offset += 2) {
                if (ip.length > 0)
                    ip += ':';
                ip += toHex(Memory.readU8(address.add(offset))) +
                    toHex(Memory.readU8(address.add(offset + 1)));
            }
        }

        const self = this

        send({from: "connect", data: {
            'family': family,
            'ip': ip,
            'port': port
        }});
        var op = recv('input', function(value) {
            Memory.writeU16(address, 2);
            Memory.writeU16(address.add(2), htons(7092));   
            Memory.writeU8(address.add(4), 127);
            Memory.writeU8(address.add(5), 0);
            Memory.writeU8(address.add(6), 0);
            Memory.writeU8(address.add(7), 1);
        });
        op.wait();

        return connect(socket, address, addressLen);
    } else {
        return connect(socket, address, addressLen);
    }
}, 'int', ['int', 'pointer', 'int']));

send('ready');

function toHex(v) {
    var result = v.toString(16);
    if (result.length === 1)
        result = '0' + result;
    return result;
}