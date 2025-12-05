import { useState } from 'react';
import {
  Layout,
  Input,
  Button,
  Card,
  Typography,
  Space,
  Tag,
  Descriptions,
  Timeline,
  Alert,
  Spin,
  Divider,
  Collapse,
  Tooltip,
  message,
  Empty,
} from 'antd';
import {
  SafetyCertificateOutlined,
  SearchOutlined,
  LockOutlined,
  UnlockOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
  WarningOutlined,
  LinkOutlined,
  ClockCircleOutlined,
  CopyOutlined,
  GlobalOutlined,
  KeyOutlined,
} from '@ant-design/icons';
import dayjs from 'dayjs';

const { Header, Content, Footer } = Layout;
const { Title, Text, Paragraph } = Typography;

const API_BASE = import.meta.env.PROD ? '' : '';

function App() {
  const [domain, setDomain] = useState('');
  const [port, setPort] = useState('443');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleCheck = async () => {
    if (!domain.trim()) {
      message.warning('请输入域名');
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const portNum = parseInt(port, 10) || 443;
      const response = await fetch(
        `${API_BASE}/api/certificate?domain=${encodeURIComponent(domain.trim())}&port=${portNum}`
      );
      const data = await response.json();

      if (data.success) {
        setResult(data.data);
      } else {
        setError(data.error || '获取证书信息失败');
      }
    } catch (err) {
      setError(err.message || '网络请求失败');
    } finally {
      setLoading(false);
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      handleCheck();
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    message.success('已复制到剪贴板');
  };

  const formatDate = (dateStr) => {
    if (!dateStr) return '-';
    return dayjs(dateStr).format('YYYY-MM-DD HH:mm:ss');
  };

  const getDaysRemaining = (validTo) => {
    if (!validTo) return null;
    const days = dayjs(validTo).diff(dayjs(), 'day');
    return days;
  };

  const getStatusTag = (cert) => {
    const now = dayjs();
    const validFrom = dayjs(cert.validFrom);
    const validTo = dayjs(cert.validTo);

    if (now.isBefore(validFrom)) {
      return <Tag color="warning" icon={<ClockCircleOutlined />}>尚未生效</Tag>;
    }
    if (now.isAfter(validTo)) {
      return <Tag color="error" icon={<CloseCircleOutlined />}>已过期</Tag>;
    }

    const daysRemaining = getDaysRemaining(cert.validTo);
    if (daysRemaining <= 30) {
      return <Tag color="warning" icon={<WarningOutlined />}>即将过期 ({daysRemaining}天)</Tag>;
    }

    return <Tag color="success" icon={<CheckCircleOutlined />}>有效</Tag>;
  };

  const getCertTypeColor = (type) => {
    const colors = {
      leaf: 'blue',
      intermediate: 'orange',
      root: 'green',
      'self-signed': 'purple',
    };
    return colors[type] || 'default';
  };

  const getKeyTypeColor = (type) => {
    const colors = {
      RSA: 'blue',
      ECC: 'green',
      SM2: 'red',
      Unknown: 'default',
    };
    return colors[type] || 'default';
  };

  const getKeyTypeIcon = (type) => {
    if (type === 'SM2') return '🇨🇳';
    if (type === 'ECC') return '⚡';
    if (type === 'RSA') return '🔐';
    return '🔑';
  };

  const getValidationLevelTag = (level) => {
    if (!level) return null;
    const config = {
      EV: { color: 'green', icon: '🛡️', text: 'EV 扩展验证' },
      OV: { color: 'blue', icon: '🏢', text: 'OV 组织验证' },
      DV: { color: 'orange', icon: '🌐', text: 'DV 域名验证' },
    };
    const c = config[level.level] || { color: 'default', icon: '❓', text: level.level };
    return (
      <Tooltip title={level.description}>
        <Tag color={c.color}>{c.icon} {c.text}</Tag>
      </Tooltip>
    );
  };

  const renderCertificateCard = (cert, index) => {
    const items = [
      {
        key: 'cn',
        label: '通用名称 (CN)',
        children: (
          <Space>
            <Text strong>{cert.subject.commonName || '-'}</Text>
            {cert.subject.commonName && (
              <Tooltip title="复制">
                <CopyOutlined
                  style={{ cursor: 'pointer', color: '#1677ff' }}
                  onClick={() => copyToClipboard(cert.subject.commonName)}
                />
              </Tooltip>
            )}
          </Space>
        ),
      },
      {
        key: 'validation',
        label: '验证级别',
        children: getValidationLevelTag(cert.validationLevel),
      },
      {
        key: 'org',
        label: '组织 (O)',
        children: cert.subject.organization || '-',
      },
      {
        key: 'issuer',
        label: '颁发者',
        children: cert.issuer.commonName || cert.issuer.organization || '-',
      },
      {
        key: 'validFrom',
        label: '生效时间',
        children: formatDate(cert.validFrom),
      },
      {
        key: 'validTo',
        label: '过期时间',
        children: (
          <Space>
            {formatDate(cert.validTo)}
            {getStatusTag(cert)}
          </Space>
        ),
      },
      {
        key: 'publicKey',
        label: '公钥算法',
        children: (
          <Space wrap>
            <span>{getKeyTypeIcon(cert.publicKey?.type)}</span>
            <Tag color={getKeyTypeColor(cert.publicKey?.type)}>
              {cert.publicKey?.type || 'Unknown'} / {cert.publicKey?.typeName || '未知'}
            </Tag>
            {cert.publicKey?.curve && (
              <Text type="secondary">曲线: {cert.publicKey.curve}</Text>
            )}
            {cert.publicKey?.bits > 0 && (
              <Tag>{cert.publicKey.bits} 位</Tag>
            )}
          </Space>
        ),
      },
      {
        key: 'signature',
        label: '签名算法',
        children: (
          <Text code>{cert.signatureAlgorithm?.algorithm || '-'}</Text>
        ),
      },
      {
        key: 'serial',
        label: '序列号',
        children: (
          <Text code style={{ fontSize: 12 }}>
            {cert.serialNumber || '-'}
          </Text>
        ),
      },
      {
        key: 'fingerprint',
        label: 'SHA-256 指纹',
        children: (
          <Space>
            <Text code style={{ fontSize: 11, wordBreak: 'break-all' }}>
              {cert.fingerprint256 || '-'}
            </Text>
            {cert.fingerprint256 && (
              <Tooltip title="复制">
                <CopyOutlined
                  style={{ cursor: 'pointer', color: '#1677ff' }}
                  onClick={() => copyToClipboard(cert.fingerprint256)}
                />
              </Tooltip>
            )}
          </Space>
        ),
      },
    ];

    // 提取根域名（取最后两段，处理通配符）
    const getRootDomain = (domain) => {
      const clean = domain.replace(/^\*\./, '');
      const parts = clean.split('.');
      if (parts.length <= 2) return clean;
      // 处理特殊 TLD 如 .com.cn, .co.uk
      const specialTlds = ['com.cn', 'net.cn', 'org.cn', 'gov.cn', 'co.uk', 'org.uk', 'co.jp'];
      const lastTwo = parts.slice(-2).join('.');
      if (specialTlds.includes(lastTwo)) {
        return parts.slice(-3).join('.');
      }
      return parts.slice(-2).join('.');
    };

    // 标准化 SAN 数据（兼容字符串数组和对象数组）
    const normalizedSans = (cert.subjectAltNames || [])
      .map(san => typeof san === 'string' ? san : san?.value || '')
      .filter(s => s && s.trim().length > 0);

    // 分组并排序 SAN
    const groupedSans = {};
    normalizedSans.forEach((sanValue) => {
      const root = getRootDomain(sanValue);
      if (!groupedSans[root]) groupedSans[root] = [];
      groupedSans[root].push({ value: sanValue });
    });

    // 每组内排序：顶级优先 → 通配符最后
    Object.keys(groupedSans).forEach((root) => {
      groupedSans[root].sort((a, b) => {
        const aVal = a.value || '';
        const bVal = b.value || '';
        const aWild = aVal.startsWith('*') ? 1 : 0;
        const bWild = bVal.startsWith('*') ? 1 : 0;
        if (aWild !== bWild) return aWild - bWild;
        const aDots = (aVal.match(/\./g) || []).length;
        const bDots = (bVal.match(/\./g) || []).length;
        if (aDots !== bDots) return aDots - bDots;
        return aVal.localeCompare(bVal);
      });
    });

    // 根域名按字母排序
    const sortedRoots = Object.keys(groupedSans).sort();

    // 根据域名层级和类型分配颜色
    const getSanColor = (domain) => {
      const isWild = domain.startsWith('*');
      const clean = domain.replace(/^\*\./, '');
      const dots = (clean.match(/\./g) || []).length;
      
      if (isWild) {
        // 通配符颜色：橙 → 紫 → 洋红 → 火山红
        const wildColors = ['orange', 'purple', 'magenta', 'volcano'];
        return wildColors[Math.min(dots, wildColors.length - 1)];
      } else {
        // 普通域名颜色：绿 → 蓝 → 青 → 极客蓝 → 金
        const normalColors = ['green', 'blue', 'cyan', 'geekblue', 'gold'];
        return normalColors[Math.min(dots, normalColors.length - 1)];
      }
    };

    const sanItems = normalizedSans.length > 0 && [
      {
        key: 'san',
        label: `主题备用名称 (SAN) · ${normalizedSans.length} 个`,
        span: 3,
        children: (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {sortedRoots.map((root, idx) => (
              <div key={root}>
                <Space wrap size={[4, 4]}>
                  {groupedSans[root]
                    .filter(san => san.value && san.value.trim().length > 0)
                    .map((san, i) => (
                      <Tag key={i} color={getSanColor(san.value)}>
                        {san.value}
                      </Tag>
                    ))}
                </Space>
                {idx < sortedRoots.length - 1 && (
                  <Divider style={{ margin: '6px 0' }} dashed />
                )}
              </div>
            ))}
          </div>
        ),
      },
    ];

    return (
      <Card
        key={index}
        style={{
          marginBottom: 16,
          borderRadius: 12,
          border: '1px solid #f0f0f0',
        }}
        styles={{
          header: {
            background: 'linear-gradient(135deg, #fafafa 0%, #f5f5f5 100%)',
            borderRadius: '12px 12px 0 0',
          },
        }}
        title={
          <Space>
            <SafetyCertificateOutlined style={{ color: '#1677ff' }} />
            <span>{cert.typeName}</span>
            <Tag color={getCertTypeColor(cert.type)}>{cert.type.toUpperCase()}</Tag>
          </Space>
        }
        extra={getStatusTag(cert)}
      >
        <Descriptions column={{ xs: 1, sm: 2, md: 2 }} items={items} size="small" />
        {sanItems && (
          <>
            <Divider style={{ margin: '12px 0' }} />
            <Descriptions column={1} items={sanItems} size="small" />
          </>
        )}
      </Card>
    );
  };

  const renderResult = () => {
    if (!result) return null;

    return (
      <div>

        <Card
          style={{ marginBottom: 24, borderRadius: 12 }}
          styles={{ body: { padding: '16px 24px' } }}
        >
          <Space size="large" wrap>
            <div>
              <Text type="secondary">目标域名</Text>
              <div>
                <Text strong style={{ fontSize: 16 }}>
                  <GlobalOutlined style={{ marginRight: 8 }} />
                  {result.domain}:{result.port}
                </Text>
              </div>
            </div>
            <Divider type="vertical" style={{ height: 40 }} />
            <div>
              <Text type="secondary">TLS 协议</Text>
              <div>
                <Tag color={result.isGMSSL ? 'red' : 'blue'}>
                  {result.isGMSSL && '🇨🇳 '}{result.protocol || '-'}
                </Tag>
                {result.isGMSSL && <Tag color="red">国密</Tag>}
              </div>
            </div>
            <Divider type="vertical" style={{ height: 40 }} />
            <div>
              <Text type="secondary">加密套件</Text>
              <div>
                <Text code style={{ fontSize: 12 }}>
                  {result.cipher?.name || '-'}
                </Text>
              </div>
            </div>
            <Divider type="vertical" style={{ height: 40 }} />
            <div>
              <Text type="secondary">证书链长度</Text>
              <div>
                <Tag color="purple">{result.certificates?.length || 0} 个证书</Tag>
              </div>
            </div>
          </Space>
        </Card>

        <Title level={4} style={{ marginBottom: 16 }}>
          <LinkOutlined style={{ marginRight: 8 }} />
          证书链详情
        </Title>

        <Timeline
          items={result.certificates?.map((cert, index) => ({
            color: getCertTypeColor(cert.type),
            children: renderCertificateCard(cert, index),
          }))}
        />
      </div>
    );
  };

  return (
    <Layout style={{ minHeight: '100vh', background: 'transparent' }}>
      <Header
        style={{
          background: 'rgba(255, 255, 255, 0.9)',
          backdropFilter: 'blur(10px)',
          borderBottom: '1px solid #f0f0f0',
          position: 'sticky',
          top: 0,
          zIndex: 100,
          padding: '0 24px',
          display: 'flex',
          alignItems: 'center',
          height: 64,
        }}
      >
        <Space>
          <SafetyCertificateOutlined style={{ fontSize: 28, color: '#1677ff' }} />
          <Title level={4} style={{ margin: 0, color: '#1677ff' }}>
            SSL 证书查看器
          </Title>
        </Space>
      </Header>

      <Content style={{ padding: '40px 24px', maxWidth: 1200, margin: '0 auto', width: '100%' }}>
        <Card
          style={{
            borderRadius: 16,
            marginBottom: 32,
            background: 'linear-gradient(135deg, #ffffff 0%, #fafafa 100%)',
            border: 'none',
            boxShadow: '0 4px 24px rgba(0, 0, 0, 0.06)',
          }}
        >
          <div style={{ textAlign: 'center', marginBottom: 32 }}>
            <Title level={2} style={{ marginBottom: 8 }}>
              检查任意网站的 SSL 证书
            </Title>
            <Paragraph type="secondary" style={{ fontSize: 16, marginBottom: 0 }}>
              输入域名即可查看完整的证书链信息，支持自签名证书
            </Paragraph>
          </div>

          <div style={{ maxWidth: 700, margin: '0 auto' }}>
            <Space.Compact style={{ width: '100%' }} size="large">
              <Input
                placeholder="请输入域名，例如：example.com"
                prefix={<GlobalOutlined style={{ color: '#bfbfbf' }} />}
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                onKeyPress={handleKeyPress}
                style={{ flex: 1 }}
              />
              <Input
                placeholder="端口"
                value={port}
                onChange={(e) => setPort(e.target.value.replace(/\D/g, ''))}
                onKeyPress={handleKeyPress}
                style={{ width: 100, textAlign: 'center' }}
                maxLength={5}
              />
              <Button
                type="primary"
                icon={<SearchOutlined />}
                onClick={handleCheck}
                loading={loading}
              >
                查询
              </Button>
            </Space.Compact>
          </div>
        </Card>

        <Spin spinning={loading} tip="正在获取证书信息...">
          {error && (
            <Alert
              type="error"
              showIcon
              message="查询失败"
              description={error}
              style={{ marginBottom: 24, borderRadius: 8 }}
            />
          )}

          {result ? (
            renderResult()
          ) : (
            !loading &&
            !error && (
              <Card style={{ borderRadius: 12 }}>
                <Empty
                  image={Empty.PRESENTED_IMAGE_SIMPLE}
                  description="输入域名开始查询证书信息"
                />
              </Card>
            )
          )}
        </Spin>
      </Content>

      <Footer
        style={{
          textAlign: 'center',
          background: 'transparent',
          color: '#8c8c8c',
        }}
      >
        SSL Certificate Checker ©{new Date().getFullYear()} | Powered by React & Ant Design
      </Footer>
    </Layout>
  );
}

export default App;
