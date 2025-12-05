/**
 * 域名解析工具模块
 */
import { URL } from 'url';

/**
 * 解析输入的域名
 */
export function parseDomain(input) {
  let domain = input.trim();
  let port = 443;

  // 如果包含协议，提取域名
  if (domain.includes('://')) {
    try {
      const url = new URL(domain);
      domain = url.hostname;
      if (url.port) {
        port = parseInt(url.port, 10);
      }
    } catch {
      // 无效的 URL，继续尝试解析
    }
  }

  // 处理 domain:port 格式
  if (domain.includes(':')) {
    const parts = domain.split(':');
    domain = parts[0];
    port = parseInt(parts[1], 10) || 443;
  }

  // 移除路径
  domain = domain.split('/')[0];

  return { domain, port };
}
