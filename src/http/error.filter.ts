import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  Logger,
} from "@nestjs/common";
import { Response } from "express";
import { rpcFailure, RPC_HTTP_STATUS } from "@311/contracts";
import { randomUUID } from "node:crypto";
import { UpstreamRpcError } from "../rpc/garden-rpc.service";
import { ContextRequest } from "./request-context";

@Catch()
export class HttpErrorFilter implements ExceptionFilter {
  private readonly logger = new Logger(HttpErrorFilter.name);

  catch(exception: unknown, host: ArgumentsHost): void {
    const http = host.switchToHttp();
    const request = http.getRequest<ContextRequest>();
    const response = http.getResponse<Response>();
    const requestId = request.garden?.requestId ?? randomUUID();
    if (exception instanceof UpstreamRpcError) {
      response.status(RPC_HTTP_STATUS[exception.rpcError.code]).json({
        ok: false,
        requestId,
        error: exception.rpcError,
      });
      return;
    }
    if (exception instanceof HttpException) {
      const status = exception.getStatus();
      const code =
        status === 401
          ? "UNAUTHENTICATED"
          : status === 403
            ? "FORBIDDEN"
            : status === 429
              ? "RATE_LIMITED"
              : status === 404
                ? "NOT_FOUND"
                : status === 503
                  ? "DEPENDENCY_UNAVAILABLE"
                  : "VALIDATION_FAILED";
      response.status(status).json(rpcFailure(requestId, code, status === 503));
      return;
    }
    this.logger.error(`Unexpected HTTP error requestId=${requestId}`);
    response.status(500).json(rpcFailure(requestId, "INTERNAL_ERROR"));
  }
}
