import { Injectable, Logger, HttpException, HttpStatus } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User, UserDocument } from './schemas/user.schema';
import * as jwt from 'jsonwebtoken';
import * as nodemailer from 'nodemailer';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(@InjectModel(User.name) private readonly userModel: Model<UserDocument>) {}

  async register(user: User): Promise<string> {
    const hashedPassword = await bcrypt.hash(user.password, 10);
    user.password = hashedPassword;
    const newUser = new this.userModel(user);
    await newUser.save();
    
    const token = jwt.sign({ userId: newUser._id, email: newUser.email }, 'aaazmh1980', { expiresIn: '8h' });
    this.logger.log(`User registered: ${newUser.email}`);
    return token;
  }

  async registerAndLogin(user: User): Promise<string> {
    const hashedPassword = await bcrypt.hash(user.password, 10);
    user.password = hashedPassword;
    const newUser = new this.userModel(user);
    await newUser.save();
    
    const token = jwt.sign({ userId: newUser._id, email: newUser.email }, 'aaazmh1980', { expiresIn: '8h' });
    this.logger.log(`User registered and logged in: ${newUser.email}`);
    return token;
  }

  async login(email: string, password: string): Promise<string | null> {
    const user = await this.userModel.findOne({ email }).exec();
    if (!user) return null;

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return null;

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

  async getUserById(userId: string): Promise<User | null> {
    try {
      const user = await this.userModel.findById(userId).exec();
      return user;
    } catch (error) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }
  }

  async sendVerificationCode(email: string): Promise<void> {
    const user = await this.userModel.findOne({ email }).exec();
    if (!user) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }

    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString(); // 6 haneli doğrulama kodu
    user.verificationCode = verificationCode;
    user.codeExpiration = new Date(Date.now() + 3600000); // 1 saat geçerlilik süresi
    await user.save();

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
      subject: 'Password Reset Verification Code',
      html: `<p>Your password reset verification code is: <strong>${verificationCode}</strong></p>` 
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

  async verifyAndResetPassword(email: string, verificationCode: string, newPassword: string): Promise<void> {
    const user = await this.userModel.findOne({ email, verificationCode }).exec();
    if (!user || user.codeExpiration < new Date()) {
      throw new HttpException('Invalid or expired verification code', HttpStatus.BAD_REQUEST);
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.verificationCode = undefined;
    user.codeExpiration = undefined;
    await user.save();
  }
}
