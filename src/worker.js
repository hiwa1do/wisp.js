import { connect } from "cloudflare:sockets";

const QUEUE_SIZE = 128;
const CONTINUE_EVERY = QUEUE_SIZE / 4;
const HEADER_SIZE = 5;
const EMPTY = new Uint8Array(0);

function makePacket(type, streamId, payload = EMPTY) {
  const packet = new Uint8Array(HEADER_SIZE + payload.length);
  packet[0] = type;
  new DataView(packet.buffer).setUint32(1, streamId >>> 0, true);
  packet.set(payload, HEADER_SIZE);
  return packet;
}

function makeUint32Payload(value) {
  const payload = new Uint8Array(4);
  new DataView(payload.buffer).setUint32(0, value >>> 0, true);
  return payload;
}

function makeClosePayload(reason) {
  return new Uint8Array([reason & 0xff]);
}

async function messageBytes(data) {
  if (data instanceof ArrayBuffer) return new Uint8Array(data);

  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }

  if (typeof Blob !== "undefined" && data instanceof Blob) {
    return new Uint8Array(await data.arrayBuffer());
  }

  return null;
}

class WispSession {
  constructor(websocket) {
    this.websocket = websocket;
    this.streams = new Map();
    this.closed = false;
    this.incoming = Promise.resolve();
  }

  send(type, streamId, payload = EMPTY) {
    if (this.closed || this.websocket.readyState !== WebSocket.OPEN) {
      return false;
    }

    try {
      this.websocket.send(makePacket(type, streamId, payload));
      return true;
    } catch (error) {
      console.error("Wisp WebSocket send failed:", error);
      this.shutdown(1011, "WebSocket send failed");
      return false;
    }
  }

  sendContinue(streamId, remaining) {
    this.send(0x03, streamId, makeUint32Payload(remaining));
  }

  sendClose(streamId, reason) {
    this.send(0x04, streamId, makeClosePayload(reason));
  }

  attach() {
    this.websocket.binaryType = "arraybuffer";

    this.websocket.addEventListener("message", (event) => {
      this.incoming = this.incoming
        .then(() => this.handleMessage(event.data))
        .catch((error) => {
          console.error("Wisp message handler failed:", error);
          this.shutdown(1011, "Internal Wisp error");
        });
    });

    this.websocket.addEventListener("close", () => {
      this.shutdown(1000, "WebSocket closed", false);
    });

    this.websocket.addEventListener("error", () => {
      this.shutdown(1011, "WebSocket error", false);
    });

    // Wisp v1 initial handshake.
    this.sendContinue(0, QUEUE_SIZE);
  }

  async handleMessage(raw) {
    if (this.closed) return;

    const data = await messageBytes(raw);
    if (!data) return;

    if (data.byteLength < HEADER_SIZE) {
      this.shutdown(1002, "Malformed Wisp packet");
      return;
    }

    const type = data[0];

    const streamId = new DataView(
      data.buffer,
      data.byteOffset,
      data.byteLength
    ).getUint32(1, true);

    const payload = data.subarray(HEADER_SIZE);

    if (type === 0x01) {
      this.handleConnect(streamId, payload);
      return;
    }

    if (type === 0x02) {
      const stream = this.streams.get(streamId);
      if (stream) await this.enqueue(stream, payload.slice());
      return;
    }

    if (type === 0x04) {
      this.closeStream(streamId);
    }
  }

  handleConnect(streamId, payload) {
    if (
      streamId === 0 ||
      this.streams.has(streamId) ||
      payload.byteLength < 4
    ) {
      this.sendClose(streamId, 0x41);
      return;
    }

    const view = new DataView(
      payload.buffer,
      payload.byteOffset,
      payload.byteLength
    );

    const streamType = payload[0];
    const port = view.getUint16(1, true);

    let hostname;

    try {
      hostname = new TextDecoder("utf-8", {
        fatal: true
      }).decode(payload.subarray(3));
    } catch {
      this.sendClose(streamId, 0x41);
      return;
    }

    if (
      streamType !== 0x01 ||
      !hostname ||
      hostname.length > 253 ||
      /[\s\u0000-\u001f\u007f/\\]/.test(hostname) ||
      port < 1 ||
      port > 65535
    ) {
      // Cloudflare Workers TCP sockets do not support UDP.
      this.sendClose(streamId, 0x41);
      return;
    }

    const stream = {
      id: streamId,
      hostname,
      port,
      socket: null,
      reader: null,
      writer: null,
      queue: [],
      dataWaiters: [],
      spaceWaiters: [],
      packetsSent: 0,
      closed: false
    };

    this.streams.set(streamId, stream);
    this.openTcpStream(stream);
  }

  async openTcpStream(stream) {
    try {
      const socket = connect(
        {
          hostname: stream.hostname,
          port: stream.port
        },
        {
          secureTransport: "off",
          allowHalfOpen: true
        }
      );

      stream.socket = socket;

      await socket.opened;

      if (this.closed || stream.closed) {
        await socket.close().catch(() => {});
        return;
      }

      stream.reader = socket.readable.getReader();
      stream.writer = socket.writable.getWriter();

      this.pumpClientToTcp(stream);
      this.pumpTcpToClient(stream);

    } catch (error) {
      console.warn(
        `Wisp TCP connect failed (${stream.hostname}:${stream.port}):`,
        error
      );

      if (!stream.closed) {
        this.sendClose(stream.id, 0x42);
        this.closeStream(stream.id);
      }

      if (stream.socket) {
        await stream.socket.close().catch(() => {});
      }
    }
  }

  async enqueue(stream, data) {
    while (
      stream.queue.length >= QUEUE_SIZE &&
      !stream.closed
    ) {
      await new Promise((resolve) =>
        stream.spaceWaiters.push(resolve)
      );
    }

    if (stream.closed) return;

    stream.queue.push(data);

    const waiter = stream.dataWaiters.shift();
    if (waiter) waiter();
  }

  async dequeue(stream) {
    while (
      stream.queue.length === 0 &&
      !stream.closed
    ) {
      await new Promise((resolve) =>
        stream.dataWaiters.push(resolve)
      );
    }

    if (stream.closed || stream.queue.length === 0) {
      return null;
    }

    const data = stream.queue.shift();

    const waiter = stream.spaceWaiters.shift();
    if (waiter) waiter();

    return data;
  }

  wakeStream(stream) {
    for (const resolve of stream.dataWaiters.splice(0)) {
      resolve();
    }

    for (const resolve of stream.spaceWaiters.splice(0)) {
      resolve();
    }
  }

  async pumpClientToTcp(stream) {
    try {
      while (!stream.closed) {
        const data = await this.dequeue(stream);

        if (data === null) return;

        await stream.writer.write(data);

        stream.packetsSent++;

        if (
          stream.packetsSent % CONTINUE_EVERY === 0 &&
          !stream.closed
        ) {
          this.sendContinue(
            stream.id,
            QUEUE_SIZE - stream.queue.length
          );
        }
      }
    } catch (error) {
      if (!stream.closed) {
        console.warn(
          `Wisp TCP write failed (${stream.hostname}:${stream.port}):`,
          error
        );

        this.sendClose(stream.id, 0x03);
        this.closeStream(stream.id);
      }
    }
  }

  async pumpTcpToClient(stream) {
    try {
      while (!stream.closed) {
        const result = await stream.reader.read();

        if (result.done) break;

        const chunk = result.value;

        if (chunk && chunk.byteLength > 0) {
          if (!this.send(0x02, stream.id, chunk)) {
            return;
          }
        }
      }

      if (!stream.closed) {
        this.sendClose(stream.id, 0x02);
        this.closeStream(stream.id);
      }
    } catch (error) {
      if (!stream.closed) {
        console.warn(
          `Wisp TCP read failed (${stream.hostname}:${stream.port}):`,
          error
        );

        this.sendClose(stream.id, 0x03);
        this.closeStream(stream.id);
      }
    }
  }

  closeStream(streamId) {
    const stream = this.streams.get(streamId);

    if (!stream) return;

    this.streams.delete(streamId);

    stream.closed = true;
    stream.queue.length = 0;

    this.wakeStream(stream);

    if (stream.socket) {
      stream.socket.close().catch(() => {});
    }
  }

  shutdown(
    code = 1000,
    reason = "Closed",
    closeWebSocket = true
  ) {
    if (this.closed) return;

    this.closed = true;

    for (const streamId of Array.from(this.streams.keys())) {
      this.closeStream(streamId);
    }

    if (
      closeWebSocket &&
      this.websocket.readyState === WebSocket.OPEN
    ) {
      try {
        this.websocket.close(code, reason.slice(0, 100));
      } catch {
        // Peer may already have disconnected.
      }
    }
  }
}

export default {
  async fetch(request) {
    const url = new URL(request.url);

    if (
      request.headers.get("Upgrade")?.toLowerCase() !== "websocket"
    ) {
      return new Response(
        '<!DOCTYPE html><html><head><title>wisp.js Server</title><style>* {font-family: sans-serif;} body {max-width: 700px;}</style></head><body><h1>wisp.js Server</h1><p>This website hosts a public <a href="https://github.com/MercuryWorkshop/wisp-protocol">Wisp</a> server. It is running <a href="https://github.com/MercuryWorkshop/wisp-server-python">wisp.js</a>.</p><p><a href="https://hiwa1do.great-site.net">hiwa1do</a>.</p></body></html>',
        {
          status: 200,
          headers: {
            "Content-Type": "text/html; charset=utf-8",
            "Cache-Control": "no-store"
          }
        }
      );
    }

    if (!url.pathname.endsWith("/")) {
      return new Response(
        "Wisp endpoint paths must end with a slash.\n",
        { status: 404 }
      );
    }

    const pair = new WebSocketPair();

    const client = pair[0];
    const server = pair[1];

    server.accept();

    const session = new WispSession(server);
    session.attach();

    return new Response(null, {
      status: 101,
      webSocket: client
    });
  }
};
