import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, { cors: true });

  // setup swagger docs
  const swagConfig = new DocumentBuilder()
    .setTitle('Naiya Swagger Documentation')
    .setDescription('Naiya Swagger Documentation')
    .setVersion('1.0')
    .addBearerAuth(
      {
        type: 'http',
        scheme: 'bearer',
        name: 'Authorization',
        bearerFormat: 'JWT',
        in: 'header',
      },
      'JWT',
    )
    .build();
  SwaggerModule.setup(
    '/swagger',
    app,
    SwaggerModule.createDocument(app, swagConfig),
    {
      explorer: true,
      swaggerOptions: {
        docExpansion: 'none',
        filter: true,
        showRequestHeaders: true,
      },
    },
  );

  app.useGlobalPipes(new ValidationPipe({ whitelist: true }));
  const PORT = process.env.PORT || 3000;
  await app.listen(PORT);
}

bootstrap();