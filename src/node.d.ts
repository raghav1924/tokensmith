/**
 * Ambient Node.js and Browser Type Declarations
 * Author: Jatin Sharma (https://jatinsh.netlify.app/)
 */

declare namespace NodeJS {
  interface Process {
    argv: string[];
    version: string;
    cwd(): string;
    exit(code?: number): never;
    env: Record<string, string | undefined>;
    platform: string;
    stdout: {
      write(str: string): boolean;
    };
    stderr: {
      write(str: string): boolean;
    };
    on(event: string, listener: (...args: any[]) => void): this;
  }
  interface Timeout {}
  interface Immediate {}
}

declare const process: NodeJS.Process;
declare const console: {
  log(...args: any[]): void;
  error(...args: any[]): void;
  warn(...args: any[]): void;
  info(...args: any[]): void;
  table(...args: any[]): void;
};

declare const Buffer: {
  from(str: string | any, encoding?: string): any;
  byteLength(string: string | any, encoding?: string): number;
};

declare function setTimeout(callback: (...args: any[]) => void, ms?: number, ...args: any[]): NodeJS.Timeout;
declare function clearTimeout(timeoutId: NodeJS.Timeout): void;
declare function setInterval(callback: (...args: any[]) => void, ms?: number, ...args: any[]): NodeJS.Timeout;
declare function clearInterval(intervalId: NodeJS.Timeout): void;
declare function setImmediate(callback: (...args: any[]) => void, ...args: any[]): NodeJS.Immediate;
declare function clearImmediate(immediateId: NodeJS.Immediate): void;

declare module 'url' {
  export class URL {
    constructor(input: string, base?: string | URL);
    href: string;
    origin: string;
    protocol: string;
    username: string;
    password: string;
    host: string;
    hostname: string;
    port: string;
    pathname: string;
    search: string;
    searchParams: {
      get(name: string): string | null;
      set(name: string, value: string): void;
      has(name: string): boolean;
    };
    hash: string;
  }
}

declare module 'node:url' {
  export * from 'url';
}

declare module 'events' {
  export class EventEmitter {
    on(event: string, listener: (...args: any[]) => void): this;
    once(event: string, listener: (...args: any[]) => void): this;
    emit(event: string, ...args: any[]): boolean;
    removeListener(event: string, listener: (...args: any[]) => void): this;
    pipe?<T>(dest: T): T;
  }
}

declare module 'node:events' {
  export * from 'events';
}

declare module 'http' {
  import { EventEmitter } from 'events';

  export interface IncomingHttpHeaders {
    [header: string]: string | string[] | undefined;
  }

  export interface IncomingMessage extends EventEmitter {
    url?: string;
    method?: string;
    statusCode?: number;
    statusMessage?: string;
    headers: IncomingHttpHeaders;
    pipe<T>(dest: T): T;
    on(event: 'data', listener: (chunk: any) => void): this;
    on(event: 'end', listener: () => void): this;
    on(event: 'close', listener: () => void): this;
    on(event: 'error', listener: (err: Error) => void): this;
    destroy(err?: Error): void;
  }

  export interface ServerResponse extends EventEmitter {
    writeHead(statusCode: number, headers?: Record<string, any>): this;
    setHeader(name: string, value: string | number | readonly string[]): this;
    getHeader(name: string): number | string | string[] | undefined;
    hasHeader(name: string): boolean;
    removeHeader(name: string): void;
    write(chunk: any, callback?: (error: Error | null | undefined) => void): boolean;
    write(chunk: any, encoding: string, callback?: (error: Error | null | undefined) => void): boolean;
    end(callback?: () => void): this;
    end(chunk: any, callback?: () => void): this;
    end(chunk: any, encoding: string, callback?: () => void): this;
    flushHeaders(): void;
    destroy(err?: Error): void;
  }

  export interface Server extends EventEmitter {
    listen(port: number, callback?: () => void): this;
    listen(port: number, host?: string, callback?: () => void): this;
    close(callback?: (err?: Error) => void): this;
  }

  export interface RequestOptions {
    protocol?: string;
    hostname?: string;
    port?: number | string;
    method?: string;
    path?: string;
    headers?: Record<string, string | number | undefined>;
    timeout?: number;
  }

  export interface ClientRequest extends EventEmitter {
    write(chunk: any): boolean;
    end(chunk?: any): this;
    abort(): void;
    destroy(err?: Error): void;
    on(event: 'response', listener: (res: IncomingMessage) => void): this;
    on(event: 'error', listener: (err: Error) => void): this;
    on(event: 'timeout', listener: () => void): this;
  }

  export function createServer(requestListener?: (req: IncomingMessage, res: ServerResponse) => void): Server;
  export function request(options: RequestOptions | string | URL, callback?: (res: IncomingMessage) => void): ClientRequest;
  export function request(url: string | URL, options?: RequestOptions, callback?: (res: IncomingMessage) => void): ClientRequest;
  export function get(options: RequestOptions | string | URL, callback?: (res: IncomingMessage) => void): ClientRequest;
  export function get(url: string | URL, options?: RequestOptions, callback?: (res: IncomingMessage) => void): ClientRequest;
}

declare module 'node:http' {
  export * from 'http';
}

declare module 'https' {
  import { RequestOptions, ClientRequest, IncomingMessage } from 'http';
  export function request(options: RequestOptions | string | URL, callback?: (res: IncomingMessage) => void): ClientRequest;
  export function request(url: string | URL, options?: RequestOptions, callback?: (res: IncomingMessage) => void): ClientRequest;
  export function get(options: RequestOptions | string | URL, callback?: (res: IncomingMessage) => void): ClientRequest;
  export function get(url: string | URL, options?: RequestOptions, callback?: (res: IncomingMessage) => void): ClientRequest;
}

declare module 'node:https' {
  export * from 'https';
}

declare module 'crypto' {
  export interface Hash {
    update(data: string | any): this;
    digest(encoding?: string): any;
  }
  export interface Hmac {
    update(data: string | any): this;
    digest(encoding?: string): any;
  }
  export function randomBytes(size: number): { toString(encoding: string): string };
  export function createHash(algorithm: string): Hash;
  export function createHmac(algorithm: string, key: string | any): Hmac;
  export function timingSafeEqual(a: any, b: any): boolean;
}

declare module 'node:crypto' {
  export * from 'crypto';
}

declare module 'perf_hooks' {
  export const performance: {
    now(): number;
  };
}

declare module 'node:perf_hooks' {
  export * from 'perf_hooks';
}

declare module 'node:test' {
  export function test(name: string, fn: (t?: any) => void | Promise<void>): void;
  export function describe(name: string, fn: () => void): void;
  export function it(name: string, fn: () => void | Promise<void>): void;
  export default test;
}

declare module 'node:assert' {
  export function strictEqual<T>(actual: unknown, expected: T, message?: string | Error): void;
  export function notStrictEqual(actual: unknown, expected: unknown, message?: string | Error): void;
  export function deepStrictEqual<T>(actual: unknown, expected: T, message?: string | Error): void;
  export function ok(value: unknown, message?: string | Error): void;
  export function match(value: string, regExp: RegExp, message?: string | Error): void;
  export function throws(fn: () => any, error?: RegExp | Function | Object | Error, message?: string): void;
  const assert: {
    strictEqual: typeof strictEqual;
    notStrictEqual: typeof notStrictEqual;
    deepStrictEqual: typeof deepStrictEqual;
    ok: typeof ok;
    match: typeof match;
    throws: typeof throws;
  };
  export default assert;
}
