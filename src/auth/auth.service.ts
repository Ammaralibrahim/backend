import { Injectable, Logger, HttpException, HttpStatus } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User, UserDocument } from './schemas/user.schema';
import * as jwt from 'jsonwebtoken';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(@InjectModel(User.name) private readonly userModel: Model<UserDocument>) {}

  async register(user: User): Promise<string> {
    const newUser = new this.userModel(user);
    await newUser.save();
    
    const token = jwt.sign({ userId: newUser._id, email: newUser.email }, 'aaazmh1980', { expiresIn: '8h' });
    this.logger.log(`User registered: ${newUser.email}`);
    return token;
  }

  async registerAndLogin(user: User): Promise<string> {
    const newUser = new this.userModel(user);
    await newUser.save();
    
    const token = jwt.sign({ userId: newUser._id, email: newUser.email }, 'aaazmh1980', { expiresIn: '8h' });
    this.logger.log(`User registered and logged in: ${newUser.email}`);
    return token;
  }

  async login(email: string, password: string): Promise<string | null> {
    const user = await this.userModel.findOne({ email, password }).exec();
    if (!user) return null;

    const token = jwt.sign({ userId: user._id, email: user.email }, 'aaazmh1980', { expiresIn: '8h' });
    this.logger.log(`User logged in: ${user.email}`);
    return token;
  }

  async verifyToken(token: string): Promise<boolean> {
    try {
      const decoded = jwt.verify(token, 'aaazmh1980');
      if (typeof decoded === 'string') {
        return false; // Token verification failed
      }
  
      // We can safely assume decoded is of JwtPayload type now
      if (decoded.email) {
        this.logger.log(`Token verified: ${decoded.email}`);
      }
      
      return !!decoded;
    } catch (error) {
      return false;
    }
  }

  async resetPassword(email: string, currentPassword: string, newPassword: string): Promise<void> {
    const user = await this.userModel.findOne({ email, password: currentPassword }).exec();
    if (!user) {
      throw new Error('Invalid email or current password');
    }

    user.password = newPassword;
    await user.save();

    this.logger.log(`Password reset for user: ${email}`);
  }

  async getUserById(userId: string): Promise<User | null> {
    try {
      const user = await this.userModel.findById(userId).exec();
      return user;
    } catch (error) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }
  }
}
