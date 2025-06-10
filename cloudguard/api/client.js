/**
 * CloudGuard JavaScript Client SDK
 * Easy-to-use client for the CloudGuard API
 */

class CloudGuardClient {
  constructor(baseUrl = 'http://localhost:3000') {
    this.baseUrl = baseUrl;
    this.timeout = 300000; // 5 minutes default timeout
  }

  /**
   * Execute a full security scan
   * @param {Object} awsCredentials - AWS credentials object
   * @param {Object} scanOptions - Scan configuration options
   * @returns {Promise<Object>} Scan results
   */
  async scan(awsCredentials, scanOptions = {}) {
    const response = await this._makeRequest('/api/scan', {
      aws_credentials: awsCredentials,
      scan_options: scanOptions
    });
    return response;
  }

  /**
   * Execute a quick security scan (limited scope)
   * @param {Object} awsCredentials - AWS credentials object
   * @returns {Promise<Object>} Scan results
   */
  async quickScan(awsCredentials) {
    const response = await this._makeRequest('/api/scan/quick', {
      aws_credentials: awsCredentials
    });
    return response;
  }

  /**
   * Get scanner capabilities
   * @returns {Promise<Object>} Available services and checks
   */
  async getCapabilities() {
    const response = await this._makeRequest('/api/capabilities', null, 'GET');
    return response;
  }

  /**
   * Check API health status
   * @returns {Promise<Object>} Health status
   */
  async healthCheck() {
    const response = await this._makeRequest('/health', null, 'GET');
    return response;
  }

  /**
   * Get API documentation
   * @returns {Promise<Object>} API documentation
   */
  async getApiDocs() {
    const response = await this._makeRequest('/api/docs', null, 'GET');
    return response;
  }

  /**
   * Make HTTP request to the API
   * @private
   */
  async _makeRequest(endpoint, body = null, method = 'POST') {
    const url = `${this.baseUrl}${endpoint}`;
    
    const options = {
      method,
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'CloudGuard-Client/1.0.0'
      }
    };

    if (body) {
      options.body = JSON.stringify(body);
    }

    try {
      // Create AbortController for timeout
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.timeout);
      options.signal = controller.signal;

      const response = await fetch(url, options);
      clearTimeout(timeoutId);

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new CloudGuardError(
          errorData.message || `HTTP ${response.status}: ${response.statusText}`,
          response.status,
          errorData.code || 'HTTP_ERROR'
        );
      }

      return await response.json();

    } catch (error) {
      if (error.name === 'AbortError') {
        throw new CloudGuardError('Request timeout', 408, 'TIMEOUT');
      }
      
      if (error instanceof CloudGuardError) {
        throw error;
      }

      throw new CloudGuardError(
        error.message || 'Network error',
        0,
        'NETWORK_ERROR'
      );
    }
  }

  /**
   * Set request timeout in milliseconds
   * @param {number} timeout - Timeout in milliseconds
   */
  setTimeout(timeout) {
    this.timeout = timeout;
  }
}

/**
 * CloudGuard API Error
 */
class CloudGuardError extends Error {
  constructor(message, statusCode = 0, code = 'UNKNOWN_ERROR') {
    super(message);
    this.name = 'CloudGuardError';
    this.statusCode = statusCode;
    this.code = code;
  }
}

// Usage examples
async function exampleUsage() {
  const client = new CloudGuardClient('http://localhost:3000');

  try {
    // Check API health
    const health = await client.healthCheck();
    console.log('API Status:', health.status);

    // Get capabilities
    const capabilities = await client.getCapabilities();
    console.log('Available services:', capabilities.services);

    // Execute quick scan
    const quickResults = await client.quickScan({
      profile: 'default'
    });
    console.log('Quick scan risk score:', quickResults.summary.risk_score);

    // Execute full scan
    const fullResults = await client.scan({
      access_key_id: 'your-access-key',
      secret_access_key: 'your-secret-key',
      region: 'us-east-1'
    }, {
      regions: ['us-east-1', 'us-west-2'],
      services: ['ec2', 's3'],
      parallel_execution: true,
      max_workers: 5
    });

    // Process results
    console.log(`Full scan completed in ${fullResults.metadata.duration_seconds}s`);
    console.log(`Risk score: ${fullResults.summary.risk_score}/100`);
    console.log(`Found ${fullResults.summary.failed_checks} security issues`);

    // Filter critical findings
    const criticalFindings = fullResults.findings.filter(
      f => f.severity === 'critical' && f.status === 'FAIL'
    );

    console.log(`Critical issues: ${criticalFindings.length}`);
    criticalFindings.forEach(finding => {
      console.log(`- ${finding.title} (${finding.resource_id})`);
    });

  } catch (error) {
    if (error instanceof CloudGuardError) {
      console.error(`CloudGuard Error [${error.code}]:`, error.message);
      if (error.statusCode >= 400) {
        console.error('HTTP Status:', error.statusCode);
      }
    } else {
      console.error('Unexpected error:', error.message);
    }
  }
}

// Export for Node.js
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { CloudGuardClient, CloudGuardError };
}

// Export for browsers
if (typeof window !== 'undefined') {
  window.CloudGuardClient = CloudGuardClient;
  window.CloudGuardError = CloudGuardError;
}
