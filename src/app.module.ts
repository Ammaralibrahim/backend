import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { AuthModule } from './auth/auth.module';

@Module({
  imports: [
    MongooseModule.forRoot('mongodb+srv://ammar:alibrahim@cluster0.51i7rk6.mongodb.net/org-main'), // MongoDB bağlantı URL'i
    AuthModule,
  ],
})
export class AppModule {}
