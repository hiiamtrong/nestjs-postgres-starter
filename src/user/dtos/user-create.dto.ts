import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString, Length, MaxLength } from 'class-validator';

export class CreateUserInput {
  @ApiProperty()
  @IsNotEmpty()
  @Length(7, 15)
  @IsString()
  phone: string;

  @ApiProperty()
  @MaxLength(50)
  @IsString()
  @IsNotEmpty()
  username: string;

  @ApiProperty()
  @IsNotEmpty()
  @Length(8, 16)
  @IsString()
  password: string;
}
