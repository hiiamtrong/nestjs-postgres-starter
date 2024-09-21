import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { AppExceptionCode } from 'src/shared/exceptions/app.exception';

export class BaseApiResponseMeta {
  @ApiProperty({ type: String, example: 'GET /api/v1/abc' })
  public path: string;

  @ApiProperty({
    type: String,
    example: '123e4567-e89b-12d3-a456-426614174000',
  })
  public requestId: string;

  @ApiProperty({ type: String, example: '2024-02-20T08:00:00.000Z' })
  public timestamp: string;
}
export class BaseApiResponse<T> {
  public data: T; // Swagger Decorator is added in the extended class below, since that will override this one.

  @ApiProperty({ type: Object })
  public meta: BaseApiResponseMeta;
}

export function SwaggerBaseApiResponse<T>(type: T): typeof BaseApiResponse {
  class ExtendedBaseApiResponse<T> extends BaseApiResponse<T> {
    @ApiProperty({ type })
    public data: T;

    @ApiProperty({ type: BaseApiResponseMeta })
    public meta: BaseApiResponseMeta;
  }
  // NOTE : Overwrite the returned class name, otherwise whichever type calls this function in the last,
  // will overwrite all previous definitions. i.e., Swagger will have all response types as the same one.
  const isAnArray = Array.isArray(type) ? ' [ ] ' : '';
  Object.defineProperty(ExtendedBaseApiResponse, 'name', {
    value: `SwaggerBaseApiResponseFor ${type} ${isAnArray}`,
  });

  return ExtendedBaseApiResponse;
}

export class BaseApiErrorObject {
  @ApiProperty({ type: Number })
  public statusCode: number;

  @ApiProperty({ type: String })
  public message: string;

  @ApiPropertyOptional({ type: String })
  public localizedMessage: string;

  @ApiProperty({ type: Object })
  public details: unknown;

  @ApiProperty({ type: String })
  public code: AppExceptionCode;
}

export class BaseApiErrorResponse {
  @ApiProperty({ type: BaseApiErrorObject })
  public error: BaseApiErrorObject;

  @ApiProperty({ type: BaseApiResponseMeta })
  public meta: BaseApiResponseMeta;
}
