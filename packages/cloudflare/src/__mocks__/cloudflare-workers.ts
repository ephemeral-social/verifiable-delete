/**
 * Mock cloudflare:workers module for vitest.
 * Provides a stub DurableObject base class.
 */

export class DurableObject<_Env = unknown> {
  ctx: unknown;
  env: _Env;

  constructor(ctx: unknown, env: _Env) {
    this.ctx = ctx;
    this.env = env;
  }
}
