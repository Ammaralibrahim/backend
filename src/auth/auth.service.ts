import { Injectable, Logger } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User, UserDocument } from './schemas/user.schema';
import * as jwt from 'jsonwebtoken';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(@InjectModel(User.name) private readonly userModel: Model<UserDocument>) {}

  async register(user: User): Promise<User> {
    const newUser = new this.userModel(user);
    return newUser.save();
  }

  async login(email: string, password: string): Promise<string | null> {
    const user = await this.userModel.findOne({ email, password }).exec();
    if (!user) return null;

    const token = jwt.sign({ userId: user._id, email: user.email }, 'aaazmh1980', { expiresIn: '1h' });
    this.logger.log(`Kullanıcı giriş yaptı: ${user.email}`);
    return token;
  }

  async verifyToken(token: string): Promise<boolean> {
    try {
      const decoded = jwt.verify(token, 'aaazmh1980');
      if (typeof decoded === 'string') {
        return false; // Token doğrulama başarısız oldu
      }
  
      // decoded artık JwtPayload türünde olduğunu güvenle varsayabiliriz
      if (decoded.email) {
        this.logger.log(`Token doğrulandı: ${decoded.email}`);
      }
      
      return !!decoded;
    } catch (error) {
      return false;
    }
  }
}
