import { plainToInstance } from 'class-transformer';
import { Request } from 'express';
import { AuthStrategyValidationOutput } from 'src/auth/constants/strategy.constant';

import {
  FORWARDED_FOR_TOKEN_HEADER,
  REQUEST_ID_TOKEN_HEADER,
} from '../../constants';
import { RequestContext } from '../request-context.dto';

// Creates a RequestContext object from Request
export function createRequestContext(request: Request): RequestContext {
  const ctx = new RequestContext();
  ctx.requestID = request.header(REQUEST_ID_TOKEN_HEADER);
  ctx.url = request.url;
  ctx.ip = request.header(FORWARDED_FOR_TOKEN_HEADER)
    ? request.header(FORWARDED_FOR_TOKEN_HEADER)
    : request.ip;
  ctx.user = request.user
    ? plainToInstance(AuthStrategyValidationOutput, request.user, {})
    : null;

  return ctx;
}
