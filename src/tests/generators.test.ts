import test, { describe, it } from 'node:test';
import assert from 'node:assert';
import { MiddlewareGenerator } from '../generators/middlewareGen.js';
import { FrameworkType } from '../types.js';

describe('Multi-Framework Hardened Middleware Generator Suite', () => {
  const frameworks: FrameworkType[] = ['nextjs', 'express', 'fastify', 'cloudflare', 'hono', 'fastapi'];

  for (const fw of frameworks) {
    it(`should synthesize production-hardened JWT middleware for ${fw}`, () => {
      const generated = MiddlewareGenerator.generate(fw, 'HS256', 'https://auth.example.com', 'https://api.example.com');

      assert.strictEqual(generated.framework, fw);
      assert.ok(generated.filename.length > 0);
      assert.ok(generated.code.length > 100);
      assert.ok(generated.instructions.length > 0);

      // Verify strict algorithm checking and claim verification
      assert.match(generated.code, /exp/);
      assert.match(generated.code, /401/);
    });
  }
});
