import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class UserLoginInput {
  @IsNotEmpty()
  @ApiProperty()
  @IsString()
  @IsEmail()
  email: string;

  @IsNotEmpty()
  @ApiProperty()
  @IsString()
  password: string;
}
