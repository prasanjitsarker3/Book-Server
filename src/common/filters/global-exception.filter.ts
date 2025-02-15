// src/common/exceptions/http-exception.filter.ts
import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { Response } from 'express';
import {
  PrismaClientKnownRequestError,
  PrismaClientValidationError,
} from '@prisma/client/runtime/library';
import { ApiResponse } from '../dto/api-response.dto';

@Catch(
  HttpException,
  PrismaClientKnownRequestError,
  PrismaClientValidationError,
)
export class HttpExceptionFilter implements ExceptionFilter {
  catch(
    exception:
      | HttpException
      | PrismaClientKnownRequestError
      | PrismaClientValidationError,
    host: ArgumentsHost,
  ) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();

    let status = HttpStatus.INTERNAL_SERVER_ERROR;
    let message = 'Internal server error';

    // Handle HttpException (NestJS built-in exceptions)
    if (exception instanceof HttpException) {
      status = exception.getStatus();
      message = this.getHttpExceptionMessage(exception);
    }
    // Handle PrismaClientKnownRequestError (e.g., unique constraint violation)
    else if (exception instanceof PrismaClientKnownRequestError) {
      status = HttpStatus.BAD_REQUEST; // or another appropriate status code
      message = this.handlePrismaError(exception);
    }
    // Handle PrismaClientValidationError (e.g., invalid input data)
    else if (exception instanceof PrismaClientValidationError) {
      status = HttpStatus.BAD_REQUEST;
      message = 'Invalid input data';
    }

    // Send the standardized ApiResponse
    response.status(status).json(new ApiResponse(status, message, null));
  }

  private getHttpExceptionMessage(exception: HttpException): string {
    const response = exception.getResponse();
    if (typeof response === 'string') {
      return response;
    } else if (typeof response === 'object' && response['message']) {
      return response['message'];
    }
    return 'An error occurred';
  }

  private handlePrismaError(exception: PrismaClientKnownRequestError): string {
    switch (exception.code) {
      case 'P2002':
        return `Unique constraint violation: ${exception.meta?.target}`;
      case 'P2025':
        return `Record not found: ${exception.meta?.cause}`;
      case 'P2003':
        return `Foreign key constraint failed: ${exception.meta?.field_name}`;
      default:
        return `Prisma error: ${exception.message}`;
    }
  }
}
