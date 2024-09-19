import { ApiProperty } from '@nestjs/swagger';
import { Expose } from 'class-transformer';

export class OperatorOutput {
  @Expose()
  @ApiProperty()
  id: number;

  @Expose()
  @ApiProperty()
  email: string;

  @Expose()
  @ApiProperty()
  roles: string[];

  @Expose()
  @ApiProperty()
  status: string;

  @Expose()
  @ApiProperty()
  metadata: Record<string, any>;

  @Expose()
  @ApiProperty()
  createdAt: Date;

  @Expose()
  @ApiProperty()
  updatedAt: Date;
}
