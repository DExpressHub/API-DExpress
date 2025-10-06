import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { MailerModule } from '@nestjs-modules/mailer';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { JobApplicationModule } from './module/job-application/job-application.module';
import { CityModule } from './module/shared/location/city/city.module';
import { DistrictModule } from './module/shared/location/district/district.module';
import { LocationModule } from './module/shared/location/location.module';
import { ProfessionalModule } from './module/professional/professional.module';
import { AdminModule } from './module/users/admin/admin.module';
import { CompanyModule } from './module/users/company/company.module';
import { UsersModule } from './module/users/users.module';
import { PrismaModule } from './common/prisma/prisma.module';
import { AdminAuthModule } from './module/users/admin/admin-auth/admin-auth.module';
import { EmailController } from './module/shared/Email/email.controller';

import { DesiredPositionModule } from './module/shared/desired-position/desired-position.module';
import { GenderModule } from './module/shared/gender/gender.module';
import { MaritalStatusModule } from './module/shared/marital-status/marital-status.module';
import { HighestDegreeModule } from './module/shared/highest-degree/highest-degree.module';
import { CourseModule } from './module/shared/course/course.module';
import { LanguageModule } from './module/shared/language/language.module';
import { SkillModule } from './module/shared/skill/skill.module';
import { AuthModule } from './module/shared/auth/auth.module';
import { DashboardModule } from './module/dashboard/dashboard.module';
import { GeneralAvailabilityModule } from './module/shared/general-availability/general-availability.module';
import { ExperienceLevelModule } from './module/shared/experience-level/experience-level.module';
import { SectorModule } from './module/shared/sector/sector.module';
import { PermissionsModule } from './module/shared/permissions/permissions.module';
import { ProfilesModule } from './module/shared/roles/profiles.module';
import { FrontendUrlModule } from './module/shared/config/frontend-url/frontend-url.module';
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';
import { APP_GUARD } from '@nestjs/core';
import { PackageModule } from './module/shared/package/package.module';
import { ClientsModule } from './module/users/clients/clients.module';
import { ServiceRequestModule } from './module/service-request/service-request.module';
import { FileService } from './module/shared/upload/file.service';
import { FileController } from './module/shared/upload/file.controller';
import { ContractModule } from './module/contract/contract.module';
import { NewsletterSubscriberModule } from './module/newsletter-subscriber/newsletter-subscriber.module';
import { TemplateContractModule } from './module/contract/model-contract/template.module';
import { ScheduleModule } from './module/shared/schedule/schedule.module';
import { AuditLogModule } from './module/shared/auditLog/auditLog.module';

import { NotificationModule } from './module/shared/notification/notification.module';



@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    MailerModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        transport: {
          host: config.get<string>('MAIL_HOST'),
          port: config.get<number>('MAIL_PORT'),
          secure: config.get<string>('MAIL_SECURE') === 'true',
          auth: {
            user: config.get<string>('MAIL_USER'),
            pass: config.get<string>('MAIL_PASS'),
          },
          
          options: {
            connectionTimeout: 60000, 
          }
        },
        defaults: {
          from: `"Suporte DExpress" <${config.get<string>('MAIL_USER')}>`,
        },
      }),
    }),
    ThrottlerModule.forRoot([
      {
        ttl: 60,
        limit: 10,
      },
    ]),
 
    ScheduleModule,
    AuthModule,
    ProfessionalModule,
    CityModule,
    DistrictModule,
    LocationModule,
    JobApplicationModule,
    ClientsModule,
    CompanyModule,
    AdminModule,
    UsersModule,
    AdminAuthModule,
    PrismaModule,
    DesiredPositionModule,
    GenderModule,
    MaritalStatusModule,
    HighestDegreeModule,
    CourseModule,
    LanguageModule,
    SkillModule,
    DashboardModule,
    GeneralAvailabilityModule,
    ExperienceLevelModule,
    SectorModule,
    PermissionsModule,
    ProfilesModule,
    FrontendUrlModule,
    PackageModule,
    ServiceRequestModule,
    ContractModule,
    NewsletterSubscriberModule,
    TemplateContractModule,
       AuditLogModule,
       NotificationModule, 
  ],
  controllers: [AppController, EmailController,FileController],
  providers: [
    AppService,FileService,
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
  
  ],
})

export class AppModule {}