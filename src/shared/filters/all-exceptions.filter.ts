import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { AppConfigService } from 'src/shared/configs/config.service';
import {
  AppException,
  AppExceptionCode,
} from 'src/shared/exceptions/app.exception';

import { REQUEST_ID_TOKEN_HEADER } from '../constants';
import { AppLogger } from '../logger/logger.service';
import { createRequestContext } from '../request-context/util';

@Catch()
export class AllExceptionsFilter<T> implements ExceptionFilter {
  /** set logger context */
  constructor(
    private config: AppConfigService,
    private readonly logger: AppLogger,
  ) {
    this.logger.setContext(AllExceptionsFilter.name);
  }

  catch(exception: T, host: ArgumentsHost): any {
    const ctx = host.switchToHttp();
    const req: Request = ctx.getRequest<Request>();
    const res: Response = ctx.getResponse<Response>();
    const acceptedLanguage = req.headers['accept-language'];
    const path = req.url;
    const timestamp = new Date().toISOString();
    const requestId = req.headers[REQUEST_ID_TOKEN_HEADER];
    const requestContext = createRequestContext(req);

    let stack: any;
    let statusCode: HttpStatus;
    let message: string;
    let details: string | Record<string, any>;
    let code: AppExceptionCode;
    // TODO : Based on language value in header, return a localized message.
    let localizedMessage: string;

    // TODO : Refactor the below cases into a switch case and tidy up error response creation.
    if (exception instanceof AppException) {
      statusCode = exception.getStatus();
      message = exception.message;
      code = exception.code;
      localizedMessage = exception.localizedMessage
        ? exception.localizedMessage[acceptedLanguage]
        : '';
      details = exception.details || exception.getResponse();
    } else if (exception instanceof HttpException) {
      statusCode = exception.getStatus();
      message = exception.message;
      details = exception.getResponse();
    } else if (exception instanceof Error) {
      message = exception.message;
      stack = exception.stack;
      code = AppExceptionCode.INTERNAL_SERVER_ERROR;
    }

    // Set to internal server error in case it did not match above categories.
    statusCode = statusCode || HttpStatus.INTERNAL_SERVER_ERROR;
    message = message || 'Internal server error';

    // NOTE: For reference, please check https://cloud.google.com/apis/design/errors
    const error = {
      statusCode,
      message,
      localizedMessage,
      details,
      code,
      // Additional meta added by us.
    };
    this.logger.warn(requestContext, error.message, {
      error,
      stack,
    });

    // Suppress original internal server error details in prod mode
    const isProMood = this.config.app.env !== 'development';
    if (isProMood && statusCode === HttpStatus.INTERNAL_SERVER_ERROR) {
      error.message = 'Internal server error';
    }

    res.status(statusCode).json({
      error,
      meta: {
        path,
        requestId,
        timestamp,
      },
    });
  }
}
