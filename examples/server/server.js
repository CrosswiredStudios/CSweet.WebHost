const http = require('node:http');
http.createServer((req, res) => {
  res.setHeader('Content-Type', req.url === '/health' ? 'application/json' : 'text/html');
  res.end(req.url === '/health' ? '{"healthy":true}' : '<!doctype html><title>Product preview</title><h1>WebHost preview</h1>');
}).listen(8080, '0.0.0.0');
