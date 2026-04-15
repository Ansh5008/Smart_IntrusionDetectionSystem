"use client";

import { useState, useEffect, useRef, useCallback } from "react";

interface WSOptions {
  url: string;
  maxBuffer?: number;
}

export function useWebSocket<T = Record<string, unknown>>(opts: WSOptions) {
  const [data, setData] = useState<T[]>([]);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const retriesRef = useRef(0);
  const maxBuffer = opts.maxBuffer ?? 500;

  const connect = useCallback(() => {
    try {
      const ws = new WebSocket(opts.url);
      wsRef.current = ws;

      ws.onopen = () => {
        setConnected(true);
        retriesRef.current = 0;
      };

      ws.onmessage = (event) => {
        try {
          const parsed = JSON.parse(event.data) as T;
          setData((prev) => {
            const next = [parsed, ...prev];
            return next.length > maxBuffer ? next.slice(0, maxBuffer) : next;
          });
        } catch {}
      };

      ws.onclose = () => {
        setConnected(false);
        const delay = Math.min(1000 * 2 ** retriesRef.current, 30000);
        retriesRef.current++;
        setTimeout(connect, delay);
      };

      ws.onerror = () => ws.close();
    } catch {}
  }, [opts.url, maxBuffer]);

  useEffect(() => {
    connect();
    return () => {
      wsRef.current?.close();
    };
  }, [connect]);

  const clear = useCallback(() => setData([]), []);

  return { data, connected, clear };
}
