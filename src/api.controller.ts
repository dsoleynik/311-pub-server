import { Inject } from "@nestjs/common";
import { PUBLIC_CONFIG, type PublicConfig } from "./config";
import {
  Body,
  Controller,
  Get,
  Post,
  Req,
  Res,
  Param,
  BadRequestException,
  UnauthorizedException,
  HttpCode,
} from "@nestjs/common";
import { Response } from "express";
import { z } from "zod";
import { CommandSchema, type Query } from "@311/contracts";
import { AuthService } from "./auth/auth.service";
import { BrowserRequestSecurity } from "./auth/browser-request-security";
import { GardenRpcService } from "./rpc/garden-rpc.service";
import { ContextRequest } from "./http/request-context";
@Controller()
export class ApiController {
  constructor(
    @Inject(PUBLIC_CONFIG) private readonly config: PublicConfig,
    private readonly auth: AuthService,
    private readonly browser: BrowserRequestSecurity,
    private readonly core: GardenRpcService,
  ) {}
  private async token(req: ContextRequest, backoffice: boolean) {
    if (backoffice) {
      const m = /^Bearer ([^\s]{1,16384})$/.exec(
        req.headers.authorization ?? "",
      );
      if (!m) throw new UnauthorizedException();
      return m[1]!;
    }
    return (await this.auth.current(this.browser.id(req))).accessToken;
  }
  private async query(req: ContextRequest, q: Query, backoffice = false) {
    return {
      ok: true,
      requestId: req.garden.requestId,
      ...(await this.core.call(
        await this.token(req, backoffice),
        q,
        undefined,
        backoffice,
      )),
    };
  }
  @Get("push/config") async pushConfig(@Req() req: ContextRequest) {
    await this.token(req, false);
    return {
      ok: true,
      requestId: req.garden.requestId,
      data: { publicKey: this.config.VAPID_PUBLIC_KEY ?? null },
    };
  }
  @Get("workspace") workspace(@Req() req: ContextRequest) {
    return this.query(req, { type: "workspace" });
  }
  @Get("backoffice/crew") staff(@Req() req: ContextRequest) {
    return this.query(req, { type: "crew.list" }, true);
  }
  @Get("backoffice/workspace") boWorkspace(@Req() req: ContextRequest) {
    return this.query(req, { type: "workspace" }, true);
  }
  @Get("jobs/:id/messages") messages(
    @Req() req: ContextRequest,
    @Param("id") id: string,
  ) {
    if (!z.uuid().safeParse(id).success) throw new BadRequestException();
    return this.query(req, { type: "messages", jobId: id });
  }
  @Get("backoffice/jobs/:id/messages") boMessages(
    @Req() req: ContextRequest,
    @Param("id") id: string,
  ) {
    if (!z.uuid().safeParse(id).success) throw new BadRequestException();
    return this.query(req, { type: "messages", jobId: id }, true);
  }
  @Get(["jobs/:id/photos/:photoId", "backoffice/jobs/:id/photos/:photoId"])
  async photo(
    @Req() req: ContextRequest,
    @Param("id") id: string,
    @Param("photoId") photoId: string,
    @Res() res: Response,
  ) {
    if (!z.uuid().safeParse(id).success || !z.uuid().safeParse(photoId).success)
      throw new BadRequestException();
    const bo = req.path.includes("/backoffice/");
    const result = await this.core.call(
      await this.token(req, bo),
      { type: "photo", jobId: id, photoId },
      undefined,
      bo,
    );
    res.type("image/jpeg").send(Buffer.from(result.data.jpeg, "base64"));
  }
  @Post(["commands", "backoffice/commands"])
  @HttpCode(200)
  async command(@Req() req: ContextRequest, @Body() raw: unknown) {
    const backoffice = req.path.includes("/backoffice/");
    if (!backoffice) await this.browser.csrf(req, this.browser.id(req));
    if (!req.is("application/json")) throw new BadRequestException();
    const key = z.uuid().safeParse(req.headers["idempotency-key"]),
      input = CommandSchema.safeParse(raw);
    if (!key.success || !input.success) throw new BadRequestException();
    return {
      ok: true,
      requestId: req.garden.requestId,
      ...(await this.core.call(
        await this.token(req, backoffice),
        input.data,
        key.data,
        backoffice,
      )),
    };
  }
}
