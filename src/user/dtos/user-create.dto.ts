import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsString, Length } from 'class-validator';

export class CreateUserInput {
  @ApiProperty()
  @IsNotEmpty()
  @IsString()
  @IsEmail()
  email: string;

  @ApiProperty()
  @IsNotEmpty()
  @Length(8, 16)
  @IsString()
  password: string;
}
