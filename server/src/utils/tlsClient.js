/**
 * TLS 连接和证书链获取模块
 */
import tls from 'tls';
import { spawn } from 'child_process';
import { parseCertificate } from './certParser.js';

// 尝试多种 TLS 配置
const TLS_CONFIGS = [
  { minVersion: 'TLSv1.2', maxVersion: 'TLSv1.3' },
  { minVersion: 'TLSv1', maxVersion: 'TLSv1.3' },
  { minVersion: 'TLSv1.2', maxVersion: 'TLSv1.3', ciphers: 'ALL' },
];

// OpenSSL/Tongsuo 命令路径
const OPENSSL_CMD = process.env.OPENSSL_CMD || 'openssl';

/**
 * 尝试使用不同配置连接
 */
function tryConnect(domain, port, timeout, configIndex = 0) {
  return new Promise((resolve, reject) => {
    if (configIndex >= TLS_CONFIGS.length) {
      return reject(new Error('无法建立 TLS 连接'));
    }

    const config = TLS_CONFIGS[configIndex];
    const socket = tls.connect({
      host: domain,
      port,
      servername: domain,
      rejectUnauthorized: false,
      timeout,
      ...config,
    }, () => {
      resolve(socket);
    });

    socket.on('error', () => {
      socket.destroy();
      tryConnect(domain, port, timeout, configIndex + 1)
        .then(resolve)
        .catch(reject);
    });

    socket.on('timeout', () => {
      socket.destroy();
      reject(new Error('连接超时'));
    });
  });
}

/**
 * 获取证书链
 */
export async function getCertificateChain(domain, port = 443, timeout = 10000) {
  const socket = await tryConnect(domain, port, timeout);
  const certificates = [];

  try {
    const peerCertificate = socket.getPeerCertificate(true);

    if (!peerCertificate || Object.keys(peerCertificate).length === 0) {
      throw new Error('无法获取证书信息');
    }

    // 遍历证书链
    let cert = peerCertificate;
    const seen = new Set();

    while (cert && !seen.has(cert.fingerprint256)) {
      seen.add(cert.fingerprint256);
      const parsedCert = parseCertificate(cert);

      if (certificates.length === 0) {
        parsedCert.type = 'leaf';
        parsedCert.typeName = '服务器证书';
      } else if (cert.issuerCertificate === cert || !cert.issuerCertificate) {
        parsedCert.type = 'root';
        parsedCert.typeName = '根证书';
      } else {
        parsedCert.type = 'intermediate';
        parsedCert.typeName = '中间证书';
      }

      certificates.push(parsedCert);
      cert = cert.issuerCertificate;

      if (certificates.length > 10) break;
    }

    // 检查是否为自签名证书
    const isSelfSigned = certificates.length === 1 &&
      certificates[0].subject.commonName === certificates[0].issuer.commonName;

    if (isSelfSigned) {
      certificates[0].type = 'self-signed';
      certificates[0].typeName = '自签名证书';
    }

    const isAuthorized = socket.authorized;
    const authorizationError = socket.authorizationError;
    const protocol = socket.getProtocol();
    const cipher = socket.getCipher();

    return {
      domain,
      port,
      certificates,
      isValid: isAuthorized,
      isSelfSigned,
      error: authorizationError || null,
      protocol,
      cipher,
    };
  } finally {
    socket.destroy();
  }
}

/**
 * 使用外部 OpenSSL/Tongsuo 命令获取证书（支持国密 GMTLS）
 */
function execOpenSSL(args, timeout = 15000, stdinData = null) {
  return new Promise((resolve, reject) => {
    const proc = spawn(OPENSSL_CMD, args);
    let stdout = '';
    let stderr = '';

    proc.stdout.on('data', (data) => { stdout += data.toString(); });
    proc.stderr.on('data', (data) => { stderr += data.toString(); });

    const timer = setTimeout(() => {
      proc.kill();
      reject(new Error('命令执行超时'));
    }, timeout);

    proc.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });

    proc.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });

    // 写入 stdin 数据
    if (stdinData) {
      proc.stdin.write(stdinData);
    } else {
      proc.stdin.write('Q\n');
    }
    proc.stdin.end();
  });
}

/**
 * 使用 Tongsuo/OpenSSL 获取国密证书
 */
async function getGMCertificateChain(domain, port = 443) {
  // 先尝试国密 NTLS 协议
  let result = await execOpenSSL([
    's_client',
    '-connect', `${domain}:${port}`,
    '-servername', domain,
    '-showcerts',
    '-enable_ntls',
    '-ntls',
  ]).catch(() => null);

  // 如果 NTLS 失败，尝试普通连接
  if (!result || !result.stdout.includes('BEGIN CERTIFICATE')) {
    result = await execOpenSSL([
      's_client',
      '-connect', `${domain}:${port}`,
      '-servername', domain,
      '-showcerts',
    ]);
  }

  if (!result.stdout.includes('BEGIN CERTIFICATE')) {
    throw new Error('无法获取证书信息');
  }

  return await parseOpenSSLOutput(result.stdout, result.stderr, domain, port);
}

/**
 * 使用 openssl x509 解析单个 PEM 证书
 */
async function parsePEMCertificate(pem) {
  try {
    const result = await execOpenSSL([
      'x509',
      '-noout',
      '-text',
      '-nameopt', 'utf8,sep_comma_plus',
      '-fingerprint',
      '-sha256',
    ], 5000, pem);

    const text = result.stdout + result.stderr;
    
    // 解析主题
    const subjectMatch = text.match(/Subject:\s*(.+)/i);
    const subject = subjectMatch ? parseDNFromText(subjectMatch[1]) : { commonName: 'Unknown' };
    
    // 解析颁发者
    const issuerMatch = text.match(/Issuer:\s*(.+)/i);
    const issuer = issuerMatch ? parseDNFromText(issuerMatch[1]) : { commonName: 'Unknown' };
    
    // 解析有效期
    const notBeforeMatch = text.match(/Not Before:\s*(.+)/i);
    const notAfterMatch = text.match(/Not After\s*:\s*(.+)/i);
    const validFrom = notBeforeMatch ? formatCertDate(notBeforeMatch[1]) : null;
    const validTo = notAfterMatch ? formatCertDate(notAfterMatch[1]) : null;
    
    // 解析序列号
    const serialMatch = text.match(/Serial Number:\s*\n?\s*([a-f0-9:]+)/i);
    const serialNumber = serialMatch ? serialMatch[1].replace(/:/g, '').toUpperCase() : '';
    
    // 解析指纹
    const fingerprintMatch = text.match(/sha256 Fingerprint=([A-F0-9:]+)/i);
    const fingerprint256 = fingerprintMatch ? fingerprintMatch[1] : '';
    
    // 解析密钥长度
    const keySizeMatch = text.match(/Public-Key:\s*\((\d+)\s*bit/i);
    
    // 解析曲线
    const curveMatch = text.match(/ASN1 OID:\s*(\S+)/i);
    const curve = curveMatch?.[1] || '';
    
    // 解析公钥算法
    const pubKeyMatch = text.match(/Public Key Algorithm:\s*(\S+)/i);
    const pubKeyAlgo = pubKeyMatch?.[1] || '';
    
    // 国密识别：检查算法名称或曲线名称
    const isGM = pubKeyAlgo.toLowerCase().includes('sm2') || 
                 curve.toLowerCase().includes('sm2') ||
                 text.toLowerCase().includes('sm2p256v1') ||
                 text.toLowerCase().includes('sm2-with-sm3');
    const isECC = !isGM && (pubKeyAlgo.includes('EC') || pubKeyAlgo.toLowerCase().includes('ec'));
    const bits = keySizeMatch ? parseInt(keySizeMatch[1]) : (isGM ? 256 : 2048);
    
    // 解析签名算法
    const sigAlgoMatch = text.match(/Signature Algorithm:\s*(\S+)/i);
    const signatureAlgorithm = sigAlgoMatch?.[1] || '';
    
    // 解析 SAN
    const sanMatch = text.match(/X509v3 Subject Alternative Name:[^\n]*\n\s*([^\n]+)/i);
    let subjectAltNames = [];
    if (sanMatch) {
      subjectAltNames = sanMatch[1]
        .split(',')
        .map(s => s.trim())
        .filter(s => s.toLowerCase().startsWith('dns:'))
        .map(s => s.replace(/^dns:/i, '').trim())
        .filter(s => s && s.length > 0); // 过滤空字符串
    }
    // 只有服务器证书才需要 SAN，CA 证书不需要
    // 不再自动用 CN 填充 SAN
    
    // 确定公钥类型
    let publicKey;
    if (isGM) {
      publicKey = {
        type: 'SM2',
        typeName: '国密 SM2',
        algorithm: 'SM2',
        curve: curve || 'sm2p256v1',
        bits: 256,
      };
    } else if (isECC) {
      publicKey = {
        type: 'ECC',
        typeName: '椭圆曲线',
        algorithm: 'ECDSA',
        curve,
        bits,
      };
    } else {
      publicKey = {
        type: 'RSA',
        typeName: '非对称加密',
        algorithm: 'RSA',
        curve: null,
        bits,
      };
    }
    
    // 确定签名算法描述
    let sigInfo;
    if (signatureAlgorithm.toLowerCase().includes('sm2') || signatureAlgorithm.toLowerCase().includes('sm3')) {
      sigInfo = { algorithm: 'SM3withSM2', description: '国密签名算法' };
    } else {
      sigInfo = { algorithm: signatureAlgorithm, description: signatureAlgorithm };
    }
    
    // 确定验证级别
    const hasOrg = !!subject.organization;
    const validationLevel = hasOrg 
      ? { level: 'OV', nameCN: '组织验证', description: '验证域名所有权和组织身份', color: 'blue' }
      : { level: 'DV', nameCN: '域名验证', description: '仅验证域名所有权', color: 'green' };
    
    return {
      subject,
      issuer,
      validFrom,
      validTo,
      serialNumber,
      fingerprint: '',
      fingerprint256,
      subjectAltNames,
      bits,
      publicKey,
      signatureAlgorithm: sigInfo,
      validationLevel,
      version: 3,
      rawPEM: pem,
      isGM,
    };
  } catch (err) {
    console.error('解析证书失败:', err.message);
    return null;
  }
}

/**
 * 格式化证书日期
 */
function formatCertDate(dateStr) {
  if (!dateStr) return null;
  try {
    const date = new Date(dateStr.trim());
    if (isNaN(date.getTime())) return dateStr.trim();
    return date.toISOString().replace('T', ' ').substring(0, 19);
  } catch {
    return dateStr.trim();
  }
}

/**
 * 从文本解析 DN
 */
function parseDNFromText(dn) {
  if (!dn) return { commonName: '' };
  // 处理格式：CN = xxx, O = xxx, C = xxx
  const cn = dn.match(/CN\s*=\s*([^,]+)/i);
  const o = dn.match(/O\s*=\s*([^,]+)/i);
  const c = dn.match(/C\s*=\s*([^,]+)/i);
  const ou = dn.match(/OU\s*=\s*([^,]+)/i);
  
  // CA 证书可能没有 CN，使用 O 或 OU 作为备选
  const commonName = cn?.[1]?.trim() || o?.[1]?.trim() || ou?.[1]?.trim() || '';
  
  return {
    commonName,
    organization: o?.[1]?.trim() || '',
    country: c?.[1]?.trim() || '',
  };
}

/**
 * 解析 OpenSSL s_client 输出
 */
async function parseOpenSSLOutput(stdout, stderr, domain, port) {
  // 提取所有证书 PEM
  const certRegex = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
  const certs = stdout.match(certRegex) || [];

  // 并行解析所有证书
  const parsedCerts = await Promise.all(certs.map(pem => parsePEMCertificate(pem)));
  
  // 过滤失败的解析结果并设置类型
  const certificates = parsedCerts
    .filter(Boolean)
    .map((cert, index, arr) => {
      if (index === 0) {
        cert.type = 'leaf';
        cert.typeName = '服务器证书';
      } else if (index === arr.length - 1) {
        cert.type = 'root';
        cert.typeName = '根证书';
      } else {
        cert.type = 'intermediate';
        cert.typeName = '中间证书';
      }
      return cert;
    });

  // 解析协议和加密套件（多种格式）
  const protocolMatch = stderr.match(/Protocol\s*:\s*(\S+)/i) || 
                        stdout.match(/Protocol\s*:\s*(\S+)/i);
  const cipherMatch = stderr.match(/Cipher\s*:\s*(\S+)/i) ||
                      stderr.match(/Cipher is\s+(\S+)/i) ||
                      stdout.match(/Cipher\s*:\s*(\S+)/i);
  
  // 检查是否使用国密
  const hasGMCert = certificates.some(c => c.isGM);
  const isNTLS = stderr.includes('NTLS') || stderr.includes('GMTLS') || 
                 stderr.includes('GMSSL') || hasGMCert;

  // 检查自签名
  const isSelfSigned = certificates.length === 1 &&
    certificates[0]?.subject?.commonName === certificates[0]?.issuer?.commonName;

  if (isSelfSigned && certificates[0]) {
    certificates[0].type = 'self-signed';
    certificates[0].typeName = '自签名证书';
  }

  // 确定加密套件名称
  let cipherName = cipherMatch?.[1] || '';
  if (!cipherName && hasGMCert) {
    cipherName = 'SM2-WITH-SM4-SM3'; // 国密默认套件
  }

  return {
    domain,
    port,
    certificates,
    isValid: true,
    isSelfSigned,
    isGMSSL: isNTLS || hasGMCert,
    error: null,
    protocol: protocolMatch?.[1] || (isNTLS || hasGMCert ? 'GMTLS' : 'TLS'),
    cipher: { name: cipherName || 'Unknown' },
  };
}

/**
 * 综合获取证书链（自动回退到国密）
 */
export async function getCertificateChainWithFallback(domain, port = 443, timeout = 10000) {
  try {
    // 先尝试 Node.js TLS
    return await getCertificateChain(domain, port, timeout);
  } catch (nodeError) {
    // Node.js TLS 失败，尝试使用外部 OpenSSL/Tongsuo
    try {
      console.log(`Node.js TLS 失败，尝试使用 ${OPENSSL_CMD}...`);
      const result = await getGMCertificateChain(domain, port);
      result.fallback = true;
      result.fallbackReason = nodeError.message;
      return result;
    } catch (opensslError) {
      // 两种方式都失败
      throw new Error(`无法获取证书信息，请检查域名是否正确`);
    }
  }
}
