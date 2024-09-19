import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsString, Length } from 'class-validator';

export class OperatorRegisterInput {
  @ApiProperty()
  @IsNotEmpty()
  @Length(7, 15)
  @IsString()
  @IsEmail()
  email: string;

  @ApiProperty()
  @IsNotEmpty()
  @Length(8, 16)
  @IsString()
  password: string;
}
