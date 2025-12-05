/**
 * 证书 API 路由
 */
import { Router } from 'express';
import { getCertificateChainWithFallback } from '../utils/tlsClient.js';
import { parseDomain } from '../utils/domainParser.js';

const router = Router();

/**
 * GET /api/certificate
 * 获取指定域名的 SSL 证书信息
 */
router.get('/certificate', async (req, res) => {
  try {
    const { domain: rawDomain, port: rawPort } = req.query;

    if (!rawDomain) {
      return res.status(400).json({
        success: false,
        error: '请提供域名参数',
      });
    }

    const { domain, port: parsedPort } = parseDomain(rawDomain);
    const port = rawPort ? parseInt(rawPort, 10) : parsedPort;

    if (!domain) {
      return res.status(400).json({
        success: false,
        error: '无效的域名',
      });
    }

    const result = await getCertificateChainWithFallback(domain, port);

    res.json({
      success: true,
      data: result,
    });
  } catch (error) {
    console.error('Certificate check error:', error);
    res.status(500).json({
      success: false,
      error: error.message || '获取证书信息失败',
    });
  }
});

/**
 * GET /api/health
 * 健康检查
 */
router.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

export default router;
