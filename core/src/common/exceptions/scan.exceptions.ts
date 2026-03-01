import { HttpException, HttpStatus } from '@nestjs/common';

export class ScanNotFoundException extends HttpException {
  constructor(scanId: string) {
    super(`Scan '${scanId}' not found`, HttpStatus.NOT_FOUND);
  }
}

export class ScanAlreadyRunningException extends HttpException {
  constructor(scanId: string) {
    super(`Scan '${scanId}' is already running`, HttpStatus.CONFLICT);
  }
}

export class ScanCancelException extends HttpException {
  constructor(scanId: string) {
    super(
      `Scan '${scanId}' cannot be cancelled in its current state`,
      HttpStatus.UNPROCESSABLE_ENTITY,
    );
  }
}

export class PythonModuleException extends HttpException {
  constructor(module: string, detail: string) {
    super(
      `Python module '${module}' returned an error: ${detail}`,
      HttpStatus.BAD_GATEWAY,
    );
  }
}
