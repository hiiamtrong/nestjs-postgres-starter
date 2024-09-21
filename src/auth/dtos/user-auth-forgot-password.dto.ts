import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class UserForgotPasswordInput {
  @ApiProperty()
  @IsString()
  @IsNotEmpty()
  @IsEmail()
  email: string;
}
