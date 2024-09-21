import { HttpException, HttpStatus } from '@nestjs/common';

export class AppException extends HttpException {
  public localizedMessage: Record<string, string>;
  public details: string | Record<string, any>;
  public code: AppExceptionCode;

  constructor(
    code: AppExceptionCode,
    message: string,
    status: number,
    details?: string | Record<string, any>,
    localizedMessage?: Record<string, string>,
  ) {
    // Calling parent constructor of base Exception class.
    super(message, status);

    this.name = AppException.name;
    this.localizedMessage = localizedMessage;
    this.details = details;
    this.code = code;
  }
}

export enum AppExceptionCode {
  BAD_REQUEST = '0400',
  INTERNAL_SERVER_ERROR = '0500',

  USER_EMAIL_ALREADY_EXISTS = '1000',
  USER_NOT_FOUND = '1001',
  USER_PASSWORD_INCORRECT = '1002',
  USER_NOT_ACTIVE = '1003',
  USER_NOT_VERIFIED = '1004',
  USER_OTP_INCORRECT = '1005',
  USER_OTP_EXPIRED = '1006',
  USER_OTP_SENT_TO_EMAIL = '1007',
  USER_ALREADY_ACTIVE = '1008',

  OPERATOR_NOT_ACTIVE = '2000',
  OPERATOR_NOT_FOUND = '2001',
  OPERATOR_ALREADY_ACTIVE = '2002',
  OPERATOR_OTP_INCORRECT = '2003',
  OPERATOR_PASSWORD_INCORRECT = '2004',
  OPERATOR_NOT_AUTHORIZED = '2005',
}

export const AppExceptions: Record<AppExceptionCode, AppException> = {
  [AppExceptionCode.BAD_REQUEST]: new AppException(
    AppExceptionCode.BAD_REQUEST,
    'Bad request',
    HttpStatus.BAD_REQUEST,
  ),

  [AppExceptionCode.INTERNAL_SERVER_ERROR]: new AppException(
    AppExceptionCode.INTERNAL_SERVER_ERROR,
    'Internal server error',
    HttpStatus.INTERNAL_SERVER_ERROR,
  ),

  [AppExceptionCode.USER_EMAIL_ALREADY_EXISTS]: new AppException(
    AppExceptionCode.USER_EMAIL_ALREADY_EXISTS,
    'User email already exists',
    HttpStatus.BAD_REQUEST,
  ),
  [AppExceptionCode.USER_NOT_FOUND]: new AppException(
    AppExceptionCode.USER_NOT_FOUND,
    'User not found',
    HttpStatus.NOT_FOUND,
  ),
  [AppExceptionCode.USER_PASSWORD_INCORRECT]: new AppException(
    AppExceptionCode.USER_PASSWORD_INCORRECT,
    'Incorrect password',
    HttpStatus.UNAUTHORIZED,
  ),
  [AppExceptionCode.USER_NOT_ACTIVE]: new AppException(
    AppExceptionCode.USER_NOT_ACTIVE,
    'User is not active',
    HttpStatus.FORBIDDEN,
  ),
  [AppExceptionCode.USER_NOT_VERIFIED]: new AppException(
    AppExceptionCode.USER_NOT_VERIFIED,
    'User is not verified',
    HttpStatus.FORBIDDEN,
  ),
  [AppExceptionCode.USER_OTP_INCORRECT]: new AppException(
    AppExceptionCode.USER_OTP_INCORRECT,
    'Incorrect OTP',
    HttpStatus.BAD_REQUEST,
  ),
  [AppExceptionCode.USER_OTP_EXPIRED]: new AppException(
    AppExceptionCode.USER_OTP_EXPIRED,
    'OTP has expired',
    HttpStatus.BAD_REQUEST,
  ),
  [AppExceptionCode.USER_OTP_SENT_TO_EMAIL]: new AppException(
    AppExceptionCode.USER_OTP_SENT_TO_EMAIL,
    'OTP sent to email',
    HttpStatus.OK,
  ),
  [AppExceptionCode.USER_ALREADY_ACTIVE]: new AppException(
    AppExceptionCode.USER_ALREADY_ACTIVE,
    'User is already active',
    HttpStatus.BAD_REQUEST,
  ),

  // New operator-related exceptions
  [AppExceptionCode.OPERATOR_NOT_ACTIVE]: new AppException(
    AppExceptionCode.OPERATOR_NOT_ACTIVE,
    'Operator is not active',
    HttpStatus.FORBIDDEN,
  ),
  [AppExceptionCode.OPERATOR_NOT_FOUND]: new AppException(
    AppExceptionCode.OPERATOR_NOT_FOUND,
    'Operator not found',
    HttpStatus.NOT_FOUND,
  ),
  [AppExceptionCode.OPERATOR_ALREADY_ACTIVE]: new AppException(
    AppExceptionCode.OPERATOR_ALREADY_ACTIVE,
    'Operator is already active',
    HttpStatus.BAD_REQUEST,
  ),
  [AppExceptionCode.OPERATOR_OTP_INCORRECT]: new AppException(
    AppExceptionCode.OPERATOR_OTP_INCORRECT,
    'Incorrect OTP for operator',
    HttpStatus.BAD_REQUEST,
  ),
  [AppExceptionCode.OPERATOR_PASSWORD_INCORRECT]: new AppException(
    AppExceptionCode.OPERATOR_PASSWORD_INCORRECT,
    'Incorrect password for operator',
    HttpStatus.UNAUTHORIZED,
  ),
  [AppExceptionCode.OPERATOR_NOT_AUTHORIZED]: new AppException(
    AppExceptionCode.OPERATOR_NOT_AUTHORIZED,
    'Operator is not authorized',
    HttpStatus.FORBIDDEN,
  ),
};

export const getAppException = (code: AppExceptionCode): AppException => {
  return (
    AppExceptions[code] || AppExceptions[AppExceptionCode.INTERNAL_SERVER_ERROR]
  );
};
