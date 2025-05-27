import { Body, Controller, Post } from '@nestjs/common';
import { UsersService } from './users.service';
import { CreateUserRequest } from './dto/create-user.request';

@Controller('users')
export class UsersController {
    constructor(private readonly usersService: UsersService) {}
  @Post()
  async createUser(@Body() request: CreateUserRequest) {
    await this.usersService.create(request)
  }
}
