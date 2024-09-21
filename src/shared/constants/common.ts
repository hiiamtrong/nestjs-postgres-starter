import { HttpStatus } from '@nestjs/common';
import { ValidationError } from 'class-validator';
import {
  AppException,
  AppExceptionCode,
} from 'src/shared/exceptions/app.exception';

export const REQUEST_ID_TOKEN_HEADER = 'x-request-id';

export const FORWARDED_FOR_TOKEN_HEADER = 'x-forwarded-for';

export const VALIDATION_PIPE_OPTIONS = {
  transform: true,
  whitelist: true,
  exceptionFactory: (validationErrors: ValidationError[] = []) => {
    throw new AppException(
      AppExceptionCode.BAD_REQUEST,
      'Bad request',
      HttpStatus.BAD_REQUEST,
      validationErrors.map((error) => ({
        field: error.property,
        error: Object.values(error.constraints).join(', '),
      })),
    );
  },
};
