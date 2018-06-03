'use strict';

Interceptor.attach(Module.findExportByName(null, 'send'), {
    onEnter: function (args) {
        var self = this;
        send({from: "enter", data: Memory.readUtf8String(args[1])});
        var op = recv('input', function(value, data) {
            var newbuf = Memory.alloc(value.size);
            Memory.writeByteArray(newbuf, data);
            args[1] = newbuf;
            self.buf = args[1];
            self.size = value.size;
            args[2] = ptr(value.size);
        });
        op.wait();
    },
    onLeave: function (result) {
        send({from: "leave", data: Memory.readUtf8String(this.buf)});
    }
});