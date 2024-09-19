import { Global, Module } from '@nestjs/common';
import { AppConfigService } from 'src/shared/configs/config.service';

@Global()
@Module({
  providers: [AppConfigService],
  exports: [AppConfigService],
})
export class AppConfigModule {}
