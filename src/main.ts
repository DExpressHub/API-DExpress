// src/main.ts
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { ValidationPipe } from '@nestjs/common';
import * as cookieParser from 'cookie-parser';
import { FrontendUrlService } from './module/shared/config/frontend-url/frontend-url.service';
import { RateLimitExceptionFilter } from './common/filters/rate-limit-exception.filter';
import * as express from 'express';
import * as crypto from 'crypto';


async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  const uerls = app.get(FrontendUrlService);

  // Prefixo global
  app.setGlobalPrefix('api');
  // Middleware para cookies
  app.use(cookieParser());

  // Define os domínios permitidos com base no ambiente
  let allowedDomains: string[];
  const productionDomain = 'https://web-site-d-express.vercel.app';

  if (process.env.COOKIES === 'production') {
    allowedDomains = [productionDomain];
  } else {
    allowedDomains = ['http://localhost:4200', 'http://localhost:5173'];
  }
  // Tenta adicionar domínios do banco de dados, mas não depende disso para funcionar
  try {
    const domainsFromDB = await uerls.getAllDomains();
    if (domainsFromDB && domainsFromDB.length > 0) {
      // Adiciona os domínios do banco de dados, mas garante que os domínios padrão
      // para o ambiente atual não sejam perdidos
      allowedDomains = [...new Set([...allowedDomains, ...domainsFromDB])];
    }
  } catch (err) {
    console.error('Atenção: Erro ao carregar domínios do banco de dados para CORS. Usando a lista de domínios padrão.', err);
  }

  console.log('Domínios CORS permitidos:', allowedDomains);

  app.enableCors({
    origin: allowedDomains, 
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true,
  });

  // Swagger config
  const config = new DocumentBuilder()
    .setTitle('DExpress')
    .setDescription('Plataforma online que conecta famílias a profissionais domésticos qualificados em Luanda')
    .setVersion('1.0')
    .addBearerAuth()
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api/docs', app, document);

  // Validação global
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );
  app.useGlobalFilters(new RateLimitExceptionFilter());
  app.use(express.json({ limit: '50mb' }));
  app.use(express.urlencoded({ limit: '50mb', extended: true }));

  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();