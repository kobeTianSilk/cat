class ServerAdapter(object):

    quiet = False

    def __init__(self, host='127.0.0.1', port=8080, **options):
        self.options = options
        self.host = host
        self.port = int(port)

    def run(self, handler): # pragma: no cover
        pass

    def __repr__(self):
        args = ', '.join(['%s=%s' % (k,repr(v)) for k, v in self.options.items()])
        return "%s(%s)" % (self.__class__.__name__, args)


class WSGIRefServer(ServerAdapter):
    def run(self, app): # pragma: no cover
        from wsgiref.simple_server import WSGIRequestHandler, WSGIServer
        from wsgiref.simple_server import make_server
        import socket

        class FixedHandler(WSGIRequestHandler):
            def address_string(self): # Prevent reverse DNS lookups please.
                return self.client_address[0]

            def log_request(*args, **kw):
                if not self.quiet:
                    return WSGIRequestHandler.log_request(*args, **kw)

        handler_cls = self.options.get('handler_class', FixedHandler)
        server_cls = self.options.get('server_class', WSGIServer)

        if ':' in self.host: # Fix wsgiref for IPv6 addresses.
            if getattr(server_cls, 'address_family') == socket.AF_INET:
                class server_cls(server_cls):
                    address_family = socket.AF_INET6

        srv = make_server(self.host, self.port, app, server_cls, handler_cls)
        srv.serve_forever()


class GeventSocketIOServer(ServerAdapter):
    def run(self,handler):
        from socketio import server
        address = (self.host, self.port)
        server.SocketIOServer(address, handler, **self.options).serve_forever()


server_names = {
    'wsgiref': WSGIRefServer,
    'geventSocketIO': GeventSocketIOServer,
}