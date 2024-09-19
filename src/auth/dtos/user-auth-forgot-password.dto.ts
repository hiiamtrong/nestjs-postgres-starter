import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class UserForgotPasswordInput {
  @ApiProperty()
  @IsString()
  @IsNotEmpty()
  phone: string;
}
