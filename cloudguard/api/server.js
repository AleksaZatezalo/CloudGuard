const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const winston = require('winston');
const morgan = require('morgan');
const { spawn } = require('child_process');
const path = require('path');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Configure logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'cloudguard-api' },
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' }),
    new winston.transports.Console({
      format: winston.format.simple()
    })
  ]
});

// Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"]
    }
  }
}));

app.use(cors({
  origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '10mb' }));
app.use(morgan('combined', { stream: { write: (message) => logger.info(message.trim()) } }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: process.env.RATE_LIMIT_MAX || 10, // limit each IP to 10 requests per windowMs
  message: {
    error: true,
    message: 'Too many scan requests from this IP, please try again later.',
    retryAfter: '15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false
});

app.use('/api/scan', limiter);

// Validation middleware
const validateScanRequest = [
  body('aws_credentials').isObject().withMessage('aws_credentials is required and must be an object'),
  body('aws_credentials.region').optional().isString().withMessage('region must be a string'),
  body('scan_options').optional().isObject().withMessage('scan_options must be an object'),
  body('scan_options.regions').optional().isArray().withMessage('regions must be an array'),
  body('scan_options.services').optional().isArray().withMessage('services must be an array'),
  body('scan_options.parallel_execution').optional().isBoolean().withMessage('parallel_execution must be boolean'),
  body('scan_options.max_workers').optional().isInt({ min: 1, max: 20 }).withMessage('max_workers must be between 1 and 20'),
  body('scan_options.timeout').optional().isInt({ min: 60, max: 1800 }).withMessage('timeout must be between 60 and 1800 seconds')
];

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    service: 'CloudGuard API',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// API documentation endpoint
app.get('/api/docs', (req, res) => {
  res.json({
    name: 'CloudGuard AWS Security Scanner API',
    version: '1.0.0',
    description: 'REST API for CloudGuard AWS security scanning',
    endpoints: {
      'GET /health': 'Health check endpoint',
      'GET /api/docs': 'API documentation',
      'GET /api/capabilities': 'List scanner capabilities',
      'POST /api/scan': 'Execute full security scan',
      'POST /api/scan/quick': 'Execute quick security scan'
    },
    authentication: 'AWS credentials required in request body',
    rateLimit: '10 requests per 15 minutes per IP'
  });
});

// Capabilities endpoint
app.get('/api/capabilities', (req, res) => {
  res.json({
    services: ['ec2', 's3'],
    checks: {
      ec2: [
        'ec2_instance_public_ip',
        'ec2_security_group_open_to_world',
        'ec2_ami_public',
        'ec2_instance_monitoring_enabled'
      ],
      s3: [
        's3_bucket_public_access',
        's3_bucket_encryption_enabled',
        's3_bucket_versioning_enabled',
        's3_bucket_logging_enabled'
      ]
    },
    supported_regions: [
      'us-east-1', 'us-west-1', 'us-west-2', 'us-east-2',
      'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1',
      'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-northeast-2',
      'ap-south-1', 'ca-central-1', 'sa-east-1'
    ],
    compliance_frameworks: ['cis', 'pci_dss', 'aws_well_architected'],
    scanner_version: '1.0.0'
  });
});

// Main scan endpoint
app.post('/api/scan', validateScanRequest, async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: true,
        message: 'Validation failed',
        details: errors.array(),
        code: 'VALIDATION_ERROR'
      });
    }

    const { aws_credentials, scan_options = {} } = req.body;
    
    logger.info('Starting security scan', { 
      regions: scan_options.regions || ['us-east-1'],
      services: scan_options.services || 'all'
    });
    
    // Execute CloudGuard scan
    const scanResult = await executeCloudGuardScan(aws_credentials, scan_options);
    
    logger.info('Scan completed successfully', {
      findings_count: scanResult.summary?.total_findings || 0,
      risk_score: scanResult.summary?.risk_score || 0
    });
    
    res.json(scanResult);
    
  } catch (error) {
    logger.error('Scan failed', { error: error.message, stack: error.stack });
    
    res.status(500).json({
      error: true,
      message: error.message || 'Internal server error',
      code: 'SCAN_FAILED',
      timestamp: new Date().toISOString()
    });
  }
});

// Quick scan endpoint (limited scope for faster results)
app.post('/api/scan/quick', validateScanRequest, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: true,
        message: 'Validation failed',
        details: errors.array()
      });
    }

    const { aws_credentials } = req.body;
    
    // Quick scan with limited scope
    const quickScanOptions = {
      services: ['ec2', 's3'],
      regions: [aws_credentials.region || 'us-east-1'],
      checks: [
        'ec2_instance_public_ip',
        'ec2_security_group_open_to_world',
        's3_bucket_public_access',
        's3_bucket_encryption_enabled'
      ],
      max_workers: 3,
      timeout: 120,
      parallel_execution: true
    };
    
    logger.info('Starting quick scan');
    
    const result = await executeCloudGuardScan(aws_credentials, quickScanOptions);
    
    logger.info('Quick scan completed', {
      findings_count: result.summary?.total_findings || 0
    });
    
    res.json(result);
    
  } catch (error) {
    logger.error('Quick scan failed', { error: error.message });
    
    res.status(500).json({
      error: true,
      message: error.message,
      code: 'QUICK_SCAN_FAILED',
      timestamp: new Date().toISOString()
    });
  }
});

// Execute CloudGuard scan using Python subprocess
async function executeCloudGuardScan(awsCredentials, scanOptions = {}) {
  return new Promise((resolve, reject) => {
    // Build command arguments
    const args = ['cloudguard', 'scan', '--quiet', '--pretty'];
    
    // Add AWS credentials
    if (awsCredentials.profile) {
      args.push('--profile', awsCredentials.profile);
    } else {
      if (awsCredentials.access_key_id) {
        args.push('--access-key-id', awsCredentials.access_key_id);
      }
      if (awsCredentials.secret_access_key) {
        args.push('--secret-access-key', awsCredentials.secret_access_key);
      }
      if (awsCredentials.session_token) {
        args.push('--session-token', awsCredentials.session_token);
      }
    }
    
    if (awsCredentials.role_arn) {
      args.push('--role-arn', awsCredentials.role_arn);
    }
    
    if (awsCredentials.external_id) {
      args.push('--external-id', awsCredentials.external_id);
    }
    
    // Add scan options
    if (scanOptions.regions && scanOptions.regions.length > 0) {
      args.push('--regions', ...scanOptions.regions);
    }
    
    if (scanOptions.services && scanOptions.services.length > 0) {
      args.push('--services', ...scanOptions.services);
    }
    
    if (scanOptions.checks && scanOptions.checks.length > 0) {
      args.push('--checks', ...scanOptions.checks);
    }
    
    if (scanOptions.excluded_services && scanOptions.excluded_services.length > 0) {
      args.push('--excluded-services', ...scanOptions.excluded_services);
    }
    
    if (scanOptions.excluded_checks && scanOptions.excluded_checks.length > 0) {
      args.push('--excluded-checks', ...scanOptions.excluded_checks);
    }
    
    if (scanOptions.max_workers) {
      args.push('--max-workers', scanOptions.max_workers.toString());
    }
    
    if (scanOptions.timeout) {
      args.push('--timeout', scanOptions.timeout.toString());
    }
    
    if (scanOptions.parallel_execution === false) {
      args.push('--no-parallel');
    }
    
    logger.debug('Executing CloudGuard command', { args: args.join(' ') });
    
    // Execute CloudGuard
    const cloudguard = spawn('python', args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: {
        ...process.env,
        // Ensure Python can find the cloudguard package
        PYTHONPATH: process.env.PYTHONPATH || ''
      }
    });
    
    let stdout = '';
    let stderr = '';
    
    cloudguard.stdout.on('data', (data) => {
      stdout += data.toString();
    });
    
    cloudguard.stderr.on('data', (data) => {
      stderr += data.toString();
    });
    
    cloudguard.on('close', (code) => {
      if (code === 0) {
        try {
          const result = JSON.parse(stdout);
          resolve(result);
        } catch (parseError) {
          logger.error('Failed to parse CloudGuard output', { stdout, parseError: parseError.message });
          reject(new Error(`Failed to parse CloudGuard output: ${parseError.message}`));
        }
      } else {
        logger.error('CloudGuard scan failed', { code, stderr, stdout });
        reject(new Error(`CloudGuard scan failed (exit code ${code}): ${stderr || 'Unknown error'}`));
      }
    });
    
    cloudguard.on('error', (error) => {
      logger.error('Failed to start CloudGuard process', { error: error.message });
      reject(new Error(`Failed to start CloudGuard: ${error.message}. Make sure CloudGuard is installed: pip install cloudguard-scanner`));
    });
    
    // Set timeout
    const timeoutMs = (scanOptions.timeout || 300) * 1000 + 30000; // Add 30s buffer
    const timeoutId = setTimeout(() => {
      cloudguard.kill('SIGTERM');
      reject(new Error('Scan timeout exceeded'));
    }, timeoutMs);
    
    cloudguard.on('close', () => {
      clearTimeout(timeoutId);
    });
  });
}

// Error handling middleware
app.use((error, req, res, next) => {
  logger.error('Unhandled error', { 
    error: error.message, 
    stack: error.stack,
    url: req.url,
    method: req.method
  });
  
  res.status(500).json({
    error: true,
    message: 'Internal server error',
    timestamp: new Date().toISOString()
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: true,
    message: 'Endpoint not found',
    available_endpoints: [
      'GET /health',
      'GET /api/docs',
      'GET /api/capabilities', 
      'POST /api/scan',
      'POST /api/scan/quick'
    ],
    documentation: '/api/docs'
  });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down gracefully');
  process.exit(0);
});

process.on('SIGINT', () => {
  logger.info('SIGINT received, shutting down gracefully');
  process.exit(0);
});

// Start server
const server = app.listen(PORT, () => {
  logger.info(`CloudGuard API server running on port ${PORT}`);
  console.log(`🛡️ CloudGuard API Server`);
  console.log(`🌐 Server: http://localhost:${PORT}`);
  console.log(`📚 API Docs: http://localhost:${PORT}/api/docs`);
  console.log(`❤️  Health: http://localhost:${PORT}/health`);
});

// Handle server errors
server.on('error', (error) => {
  logger.error('Server error', { error: error.message });
  process.exit(1);
});

module.exports = app;