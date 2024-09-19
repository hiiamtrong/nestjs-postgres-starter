import { ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsEmail,
  IsNotEmpty,
  IsOptional,
  IsString,
  Length
} from 'class-validator';
import { UserStatus } from 'src/user/entities/user.entity';

export class UpdateUserInput {
  @ApiPropertyOptional()
  @IsOptional()
  @IsNotEmpty()
  @IsEmail()
  email: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsNotEmpty()
  @Length(6, 100)
  @IsString()
  password: string;
}

export class BackofficeUpdateUserInput extends UpdateUserInput {
  @ApiPropertyOptional()
  @IsOptional()
  @IsNotEmpty()
  status: UserStatus;

  @ApiPropertyOptional()
  @IsOptional()
  metadata: Record<string, any>;

  @ApiPropertyOptional()
  @IsOptional()
  @IsNotEmpty()
  balance: number;

  @ApiPropertyOptional()
  @IsOptional()
  @IsNotEmpty()
  lockedBalance: number;

  @ApiPropertyOptional()
  @IsOptional()
  @IsNotEmpty()
  pendingBalance: number;
}
