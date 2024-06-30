import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // CORS'u etkinleştir
  app.enableCors({
    origin: 'http://localhost:4200', // Angular uygulamanızın adresini buraya ekleyin
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS',
    credentials: true,
  });

  await app.listen(3000); // Burada belirlediğiniz portu kontrol edin
}
bootstrap();
