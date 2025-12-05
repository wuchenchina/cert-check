/**
 * SSL Certificate Checker API Server
 * 入口文件
 */
import express from 'express';
import cors from 'cors';
import certificateRoutes from './routes/certificate.js';

const app = express();
const PORT = process.env.PORT || 3001;

// 中间件
app.use(cors());
app.use(express.json());

// 路由
app.use('/api', certificateRoutes);

// 启动服务
app.listen(PORT, () => {
  console.log(`🚀 Server is running on port ${PORT}`);
});
