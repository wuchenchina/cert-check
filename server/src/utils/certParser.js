/**
 * 证书解析工具模块
 */

// 国密曲线 OID 和名称
const SM2_CURVES = ['SM2', 'sm2p256v1', '1.2.156.10197.1.301'];

// EV 证书的 OID 列表（主要 CA 的 EV OID）
const EV_OIDS = [
  '2.23.140.1.1',           // CA/Browser Forum EV
  '1.3.6.1.4.1.34697.2.1',  // AffirmTrust
  '1.3.6.1.4.1.6449.1.2.1.5.1', // Comodo
  '2.16.840.1.114412.2.1',  // DigiCert
  '2.16.840.1.114028.10.1.2', // Entrust
  '1.3.6.1.4.1.14370.1.6',  // GeoTrust
  '1.3.6.1.4.1.4146.1.1',   // GlobalSign
  '2.16.840.1.114413.1.7.23.3', // GoDaddy
  '2.16.840.1.114414.1.7.23.3', // Starfield
  '2.16.756.1.89.1.2.1.1',  // SwissSign
  '1.3.6.1.4.1.8024.0.2.100.1.2', // QuoVadis
  '1.2.616.1.113527.2.5.1.1', // Certum
  '1.3.6.1.4.1.23223.1.1.1', // StartCom
  '2.16.840.1.113733.1.7.23.6', // Symantec (VeriSign)
  '2.16.840.1.114404.1.1.2.4.1', // Trustwave
  '1.3.6.1.4.1.17326.10.14.2.1.2', // Camerfirma
  '1.3.6.1.4.1.22234.2.5.2.3.1', // Izenpe
];

// 常见 ECC 曲线映射
const ECC_CURVES = {
  'prime256v1': 'P-256 (secp256r1)',
  'secp256r1': 'P-256 (secp256r1)',
  'secp384r1': 'P-384 (secp384r1)',
  'secp521r1': 'P-521 (secp521r1)',
  'secp256k1': 'secp256k1 (Bitcoin)',
  'X25519': 'X25519',
  'Ed25519': 'Ed25519',
  'X448': 'X448',
  'Ed448': 'Ed448',
};

/**
 * 解析公钥算法信息
 */
export function parsePublicKeyAlgorithm(cert) {
  if (cert.asn1Curve) {
    const curve = cert.asn1Curve;
    
    // 检查是否为国密 SM2
    if (SM2_CURVES.some(sm2 => curve.toLowerCase().includes(sm2.toLowerCase()))) {
      return {
        type: 'SM2',
        typeName: '国密 SM2',
        algorithm: 'SM2',
        curve,
        bits: 256,
        description: '中国商用密码算法',
      };
    }
    
    // 普通 ECC
    const curveName = ECC_CURVES[curve] || curve;
    let bits = 256;
    if (curve.includes('384')) bits = 384;
    else if (curve.includes('521')) bits = 521;
    else if (curve.includes('448')) bits = 448;
    
    return {
      type: 'ECC',
      typeName: '椭圆曲线',
      algorithm: 'ECDSA',
      curve: curveName,
      bits: cert.bits || bits,
      description: `椭圆曲线加密 (${curveName})`,
    };
  }
  
  // 检查是否为 RSA
  if (cert.modulus) {
    const bits = cert.bits || (cert.modulus.length * 4);
    return {
      type: 'RSA',
      typeName: '非对称加密',
      algorithm: 'RSA',
      curve: null,
      bits,
      description: `RSA ${bits} 位`,
    };
  }

  // Ed25519/Ed448 检测
  if (cert.pubkey && (cert.pubkey.length === 32 || cert.pubkey.length === 44)) {
    return {
      type: 'ECC',
      typeName: '椭圆曲线',
      algorithm: 'Ed25519',
      curve: 'Ed25519',
      bits: 256,
      description: 'Edwards-curve (Ed25519)',
    };
  }

  return {
    type: 'Unknown',
    typeName: '未知',
    algorithm: 'Unknown',
    curve: null,
    bits: cert.bits || 0,
    description: '未知算法',
  };
}

/**
 * 解析签名算法
 */
export function parseSignatureAlgorithm(cert) {
  const pubKey = parsePublicKeyAlgorithm(cert);
  
  const algorithms = {
    SM2: { algorithm: 'SM3withSM2', description: '国密签名算法' },
    ECC: { algorithm: 'ECDSA with SHA-256', description: '椭圆曲线签名' },
    RSA: { algorithm: 'SHA-256 with RSA', description: 'RSA 签名' },
  };
  
  return algorithms[pubKey.type] || { algorithm: 'Unknown', description: '未知' };
}

/**
 * 解析证书验证级别 (DV/OV/EV)
 */
export function parseValidationLevel(cert) {
  const subject = cert.subject || {};
  const infoAccess = cert.infoAccess || {};
  
  // 检查是否包含 EV OID（通过 infoAccess 或 ext_key_usage）
  const infoAccessStr = JSON.stringify(infoAccess);
  const hasEVOID = EV_OIDS.some(oid => infoAccessStr.includes(oid));
  
  // EV 证书特征：包含 EV OID 或者有完整的组织信息（O + L + ST + C）
  const hasFullOrgInfo = subject.O && subject.L && (subject.ST || subject.S) && subject.C;
  
  // 检查是否有 businessCategory 或 serialNumber（EV 特有）
  const hasEVFields = subject.businessCategory || subject.serialNumber;
  
  if (hasEVOID || (hasFullOrgInfo && hasEVFields)) {
    return {
      level: 'EV',
      name: 'Extended Validation',
      nameCN: '扩展验证',
      description: '最高级别验证，验证组织身份和法律存在性',
      color: 'green',
    };
  }
  
  // OV 证书特征：包含组织信息 (O) 但不满足 EV 条件
  if (subject.O) {
    return {
      level: 'OV',
      name: 'Organization Validation',
      nameCN: '组织验证',
      description: '验证域名所有权和组织身份',
      color: 'blue',
    };
  }
  
  // DV 证书：仅验证域名
  return {
    level: 'DV',
    name: 'Domain Validation',
    nameCN: '域名验证',
    description: '仅验证域名所有权',
    color: 'orange',
  };
}

/**
 * 解析主题/颁发者信息
 */
function parseSubject(subject) {
  if (!subject) return {};
  return {
    commonName: subject.CN || '',
    organization: subject.O || '',
    organizationalUnit: subject.OU || '',
    country: subject.C || '',
    state: subject.ST || '',
    locality: subject.L || '',
  };
}

/**
 * 解析 SAN 备用名称
 */
function parseAltNames(subjectaltname) {
  if (!subjectaltname) return [];
  return subjectaltname.split(', ').map((name) => {
    const [type, value] = name.split(':');
    return { type, value };
  });
}

/**
 * 格式化日期
 */
function formatDate(dateStr) {
  if (!dateStr) return null;
  return new Date(dateStr).toISOString();
}

/**
 * 解析单个证书信息
 */
export function parseCertificate(cert) {
  if (!cert) return null;

  const publicKeyInfo = parsePublicKeyAlgorithm(cert);
  const signatureInfo = parseSignatureAlgorithm(cert);
  const validationLevel = parseValidationLevel(cert);

  return {
    subject: parseSubject(cert.subject),
    issuer: parseSubject(cert.issuer),
    validFrom: formatDate(cert.valid_from),
    validTo: formatDate(cert.valid_to),
    serialNumber: cert.serialNumber || '',
    fingerprint: cert.fingerprint || '',
    fingerprint256: cert.fingerprint256 || '',
    subjectAltNames: parseAltNames(cert.subjectaltname),
    bits: cert.bits || publicKeyInfo.bits,
    publicKey: publicKeyInfo,
    signatureAlgorithm: signatureInfo,
    validationLevel,
    version: cert.version || 0,
    raw: cert.raw ? cert.raw.toString('base64') : '',
  };
}
