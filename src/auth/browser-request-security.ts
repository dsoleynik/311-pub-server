import {
  ForbiddenException,
  Inject,
  Injectable,
  UnauthorizedException,
} from "@nestjs/common";
import { timingSafeEqual } from "node:crypto";
import { PUBLIC_CONFIG, PublicConfig } from "../config";
import { ContextRequest } from "../http/request-context";
import { SessionStore } from "./session-store";

@Injectable()
export class BrowserRequestSecurity {
  readonly cookieName: string;
  constructor(
    private readonly sessions: SessionStore,
    @Inject(PUBLIC_CONFIG) private readonly config: PublicConfig,
  ) {
    this.cookieName =
      config.NODE_ENV === "production" ? "__Host-311_session" : "311_session";
  }
  cookieOptions() {
    return {
      httpOnly: true,
      secure:
        this.config.NODE_ENV === "production" ||
        this.config.PUBLIC_ORIGIN!.startsWith("https://"),
      sameSite: "lax" as const,
      path: "/",
    };
  }
  id(req: ContextRequest) {
    const values = (req.headers.cookie ?? "")
      .split(";")
      .map((v) => v.trim())
      .filter((v) => v.startsWith(`${this.cookieName}=`));
    if (values.length !== 1) throw new UnauthorizedException();
    const value = values[0]!.slice(this.cookieName.length + 1);
    if (!/^[A-Za-z0-9_-]{43}$/.test(value)) throw new UnauthorizedException();
    return value;
  }
  origin(req: ContextRequest) {
    if (
      req.headers.origin !== this.config.PUBLIC_ORIGIN ||
      req.headers["x-311-request"] !== "1"
    )
      throw new ForbiddenException();
  }
  async csrf(req: ContextRequest, id: string) {
    this.origin(req);
    const value = req.headers["x-311-csrf"];
    const session = await this.sessions.get(id);
    if (
      typeof value !== "string" ||
      !/^[a-f0-9]{64}$/.test(value) ||
      !timingSafeEqual(Buffer.from(value), Buffer.from(session.csrfToken))
    )
      throw new ForbiddenException();
  }
}
