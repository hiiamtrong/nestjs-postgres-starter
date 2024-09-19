import { Module } from '@nestjs/common';
import { PermissionService } from 'src/permission/permission.service';

@Module({
  controllers: [],
  providers: [PermissionService],
  exports: [PermissionService],
})
export class PermissionModule {}
