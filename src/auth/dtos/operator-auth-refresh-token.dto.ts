import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty } from 'class-validator';

export class OperatorRefreshTokenInput {
  @IsNotEmpty()
  @ApiProperty()
  refreshToken: string;
}
