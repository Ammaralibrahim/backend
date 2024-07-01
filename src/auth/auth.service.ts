import { Injectable, Logger, HttpException, HttpStatus } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User, UserDocument } from './schemas/user.schema';
import * as jwt from 'jsonwebtoken';
import * as nodemailer from 'nodemailer';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(@InjectModel(User.name) private readonly userModel: Model<UserDocument>) {}

  async register(user: User): Promise<void> {
    const newUser = new this.userModel(user);
    await newUser.save();
    this.logger.log(`User registered: ${newUser.email}`);
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
        return false;
      }
  
      if (decoded.email) {
        this.logger.log(`Token verified: ${decoded.email}`);
      }
      
      return !!decoded;
    } catch (error) {
      return false;
    }
  }

  async getUserById(userId: string): Promise<User | null> {
    try {
      const user = await this.userModel.findById(userId).exec();
      return user;
    } catch (error) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }
  }

  async sendPasswordResetEmail(email: string): Promise<void> {
    const user = await this.userModel.findOne({ email }).exec();
    if (!user) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }
  
    const token = jwt.sign({ userId: user._id }, 'aaazmh1980', { expiresIn: '1h' });
  
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: 'ammaryasir8088@gmail.com',
        pass: 'dmys mfyu fgbj vdat'
      }
    });
  
    const mailOptions = {
      from: 'ammaryasir8088@gmail.com',
      to: email,
      subject: 'Password Reset For ShopAuth',
      html: `
        <p>Hello,</p>
        <p>You requested a password reset. Please click <a href="http://localhost:4200/reset/${token}">here</a> to reset your password.</p>
        <p>If you didn't request this, please ignore this email.</p>
      `
    };
  
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('Error sending email:', error);
        throw new HttpException('Error sending email', HttpStatus.INTERNAL_SERVER_ERROR);
      } else {
        console.log('Email sent:', info.response);
      }
    });
  }

  async resetPassword(token: string, newPassword: string): Promise<void> {
    let decoded;
    try {
      decoded = jwt.verify(token, 'aaazmh1980') as { userId: string };
    } catch (error) {
      throw new HttpException('Invalid or expired token', HttpStatus.UNAUTHORIZED);
    }
  
    const user = await this.userModel.findById(decoded.userId).exec();
    if (!user) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }
  
    user.password = newPassword;
    await user.save();
    this.logger.log(`Password reset for user: ${user.email}`);
  }
}
