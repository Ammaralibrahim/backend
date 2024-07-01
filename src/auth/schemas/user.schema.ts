import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type UserDocument = User & Document;

@Schema()
export class User {
  @Prop({ required: true })
  email: string;

  @Prop({ required: true })
  password: string;

  @Prop()
  verificationCode?: string; // Doğrulama kodu alanı

  @Prop()
  codeExpiration?: Date; // Doğrulama kodu geçerlilik süresi
}

export const UserSchema = SchemaFactory.createForClass(User);
