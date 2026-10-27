import { Inject, Injectable } from "@nestjs/common";
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from "node:crypto";
import { z } from "zod";
import {
  RedisConnection,
  rpcError,
  UpstreamRpcError,
} from "@311/nest-infrastructure";
import { TokensSchema } from "@311/gravum-contracts";
import { PUBLIC_CONFIG, PublicConfig } from "../config";
const SessionSchema = TokensSchema.extend({
  csrfToken: z.string().length(64),
  accessExpiresAt: z.number(),
  revision: z.number().int().nonnegative(),
  state: z.enum(["ready", "refreshing"]),
  principalId: z.uuid(),
  erpSessionId: z.uuid(),
});
export type Session = z.infer<typeof SessionSchema>;
const RELEASE =
  "if redis.call('GET',KEYS[1]) == ARGV[1] then return redis.call('DEL',KEYS[1]) else return 0 end";
const SAVE =
  "if redis.call('GET',KEYS[1]) == ARGV[1] and redis.call('EXISTS',KEYS[2]) == 1 then redis.call('SET',KEYS[2],ARGV[2],'PX',ARGV[3]); return 1 else return 0 end";
@Injectable()
export class SessionStore {
  private readonly key: Buffer;
  constructor(
    private readonly redis: RedisConnection,
    @Inject(PUBLIC_CONFIG) private readonly config: PublicConfig,
  ) {
    this.key = config.SESSION_ENCRYPTION_KEY_BASE64
      ? Buffer.from(config.SESSION_ENCRYPTION_KEY_BASE64, "base64")
      : Buffer.alloc(32);
  }
  private name(id: string) {
    if (!/^[A-Za-z0-9_-]{43}$/.test(id)) throw rpcError("UNAUTHENTICATED");
    return `session:${createHash("sha256").update(id).digest("hex")}`;
  }
  private seal(name: string, record: Session) {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.key, iv);
    cipher.setAAD(Buffer.from(name));
    return Buffer.concat([
      iv,
      cipher.update(JSON.stringify(record)),
      cipher.final(),
      cipher.getAuthTag(),
    ]).toString("base64");
  }
  private open(name: string, raw: string): Session {
    try {
      const bytes = Buffer.from(raw, "base64");
      const decipher = createDecipheriv(
        "aes-256-gcm",
        this.key,
        bytes.subarray(0, 12),
      );
      decipher.setAAD(Buffer.from(name));
      decipher.setAuthTag(bytes.subarray(-16));
      return SessionSchema.parse(
        JSON.parse(
          Buffer.concat([
            decipher.update(bytes.subarray(12, -16)),
            decipher.final(),
          ]).toString("utf8"),
        ),
      );
    } catch {
      throw rpcError("UNAUTHENTICATED");
    }
  }
  private ttl(record: Session) {
    const ttl = Date.parse(record.sessionExpiresAt) - Date.now();
    if (ttl <= 0) throw rpcError("UNAUTHENTICATED");
    return ttl;
  }
  private async io<T>(work: () => Promise<T>): Promise<T> {
    try {
      return await work();
    } catch (e) {
      if (e instanceof UpstreamRpcError) throw e;
      throw rpcError("DEPENDENCY_UNAVAILABLE");
    }
  }
  async create(record: Session) {
    const id = randomBytes(32).toString("base64url");
    const name = this.name(id);
    await this.io(() =>
      this.redis.client.set(
        name,
        this.seal(name, record),
        "PX",
        this.ttl(record),
        "NX",
      ),
    );
    return id;
  }
  async get(id: string) {
    const name = this.name(id);
    const raw = await this.io(() => this.redis.client.get(name));
    if (!raw) throw rpcError("UNAUTHENTICATED");
    const session = this.open(name, raw);
    this.ttl(session);
    return session;
  }
  async remove(id: string) {
    await this.io(() => this.redis.client.del(this.name(id)));
  }
  async withLock<T>(
    id: string,
    handler: (
      session: Session,
      save: (next: Session) => Promise<void>,
    ) => Promise<T>,
  ) {
    const name = this.name(id),
      lock = `${name}:lock`,
      owner = randomBytes(16).toString("hex");
    const until = Date.now() + this.config.RPC_TIMEOUT_MS * 2 + 2000;
    while (
      !(await this.io(() =>
        this.redis.client.set(lock, owner, "PX", 60_000, "NX"),
      ))
    ) {
      if (Date.now() >= until) throw rpcError("RATE_LIMITED", true);
      await new Promise((resolve) => setTimeout(resolve, 30));
    }
    try {
      const current = await this.get(id);
      if (current.state !== "ready") {
        await this.remove(id);
        throw rpcError("SESSION_REVOKED");
      }
      return await handler(current, async (next) => {
        const saved = await this.io(() =>
          this.redis.client.eval(
            SAVE,
            2,
            lock,
            name,
            owner,
            this.seal(name, next),
            this.ttl(next),
          ),
        );
        if (saved !== 1) throw rpcError("SESSION_REVOKED");
      });
    } finally {
      await this.redis.client
        .eval(RELEASE, 1, lock, owner)
        .catch(() => undefined);
    }
  }
  async throttleAction(action: string, ip: string, identity: string) {
    const script =
      "local n=redis.call('INCR',KEYS[1]); if n==1 then redis.call('EXPIRE',KEYS[1],900) end; return n";
    for (const [value, limit] of [
      [`ip:${ip}`, 20],
      [`identity:${identity.toLowerCase()}`, 5],
    ] as const) {
      const key = `self-service-limit:${action}:${createHash("sha256").update(value).digest("hex")}`;
      if (
        Number(await this.io(() => this.redis.client.eval(script, 1, key))) >
        limit
      )
        throw rpcError("RATE_LIMITED");
    }
  }
  async throttle(ip: string, login: string) {
    const script =
      "local n=redis.call('INCR',KEYS[1]); if n==1 then redis.call('EXPIRE',KEYS[1],300) end; return n";
    for (const [value, limit] of [
      [`ip:${ip}`, 30],
      [`login:${login.trim().toLowerCase()}`, 10],
    ] as const) {
      const key = `auth-limit:${createHash("sha256").update(value).digest("hex")}`;
      const count = await this.io(() => this.redis.client.eval(script, 1, key));
      if (Number(count) > limit) throw rpcError("RATE_LIMITED");
    }
  }
}
