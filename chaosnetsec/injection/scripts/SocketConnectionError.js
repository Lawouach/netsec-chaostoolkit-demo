'use strict';

const AF_INET = 2;
const AF_INET6 = 30;
const ECONNREFUSED = 111;


const connect = new NativeFunction(
    Module.findExportByName(null, "connect"),
    'int', ['int', 'pointer', 'int']);

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
            if (value.errno !== null) {
                self.errno = value.errno;
            }
        });
        op.wait();

        if (this.errno === 0) {
            return connect(socket, address, addressLen);
        }

        return -1;
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