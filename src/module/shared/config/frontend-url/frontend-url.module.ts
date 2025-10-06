import { Module } from '@nestjs/common';
import { FrontendUrlService } from './frontend-url.service';
import { FrontendUrlController } from './frontend-url.controller';
import { PrismaModule } from 'src/common/prisma/prisma.module';

@Module({
  imports:[PrismaModule],
 // controllers: [FrontendUrlController],
  providers: [FrontendUrlService],
})
export class FrontendUrlModule {}
