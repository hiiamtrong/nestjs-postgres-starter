import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtOperatorAuthStrategy } from 'src/auth/strategies/jwt-operator-auth.strategy';
import { Operator } from 'src/operator/entities/operator.entity';
import { OperatorRepository } from 'src/operator/operator.repository';
import { OperatorService } from 'src/operator/operator.service';
import { PermissionModule } from 'src/permission/permission.module';

@Module({
  imports: [PermissionModule, TypeOrmModule.forFeature([Operator])],
  providers: [OperatorService, JwtOperatorAuthStrategy, OperatorRepository],
  exports: [OperatorService],
})
export class OperatorModule {}
