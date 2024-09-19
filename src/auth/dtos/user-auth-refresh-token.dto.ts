import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty } from 'class-validator';

export class UserRefreshTokenInput {
  @IsNotEmpty()
  @ApiProperty()
  refreshToken: string;
}
